//! Chain profiles — NOT RATIFIED.
//!
//! The swap-tab design (agreed with the operator) says: "a network is
//! enabled by adding a profile, not by touching the engine". This crate
//! is that profile — and it is SAFETY-CRITICAL CONFIGURATION, not
//! convenience: the numbers here are exactly what the timelock
//! validators TRUST. `ChainTimingBoundsV1` feeds the M.8 window
//! inequality (`bind_and_validate_funding_anchors`); a wrong bound does
//! not trip a refusal — it silently poisons the atomicity defence. So a
//! profile validates fail-closed, commits to a digest, and derives the
//! composed-route margins from its explicit budgets instead of letting
//! anyone hand-pick them.
//!
//! What a profile carries (design §Chain profiles):
//! - the 32-byte registry `chain_id` and the chain kind;
//! - for an EVM chain: the EVM `chain_id`, the deployed lock contracts
//!   (native and optional ERC-20) and the `keccak256` code hash the
//!   adapter must find there (`EvmAdapterConfig.expected_code_hash`);
//! - for a Bitcoin chain: the F5 network (`BitcoinNetworkV1` — an enum
//!   in which mainnet DOES NOT EXIST, by D-027; this crate cannot relax
//!   that by construction);
//! - `ChainTimingBoundsV1` — block-interval bounds and the reorg,
//!   observation and broadcast budgets;
//! - `FinalityPolicyV1` — confirmations and tolerated reorg depth;
//! - the native asset and the bounded allowed-asset list.
//!
//! What validation refuses, by name (I13): degenerate timing bounds
//! (through the SAME arithmetic the M.8 validator applies — reused, not
//! re-implemented); a finality policy the terms layer would refuse; a
//! reorg seconds budget too small to cover the finality policy's own
//! tolerated reorg depth at the slowest block interval; EVM chain id 0
//! or 1 (mainnet remains excluded — the same rule
//! `EvmAdapterConfig.validate` enforces); an unpinned (zero) code hash;
//! duplicate or unbounded asset lists.
//!
//! What the profile DERIVES: the composed-route margin floors. The
//! additive M.8 lab rule (`minimum_safety_margin_seconds`: the sum of
//! both chains' reorg + observation + broadcast budgets) is reused
//! verbatim for the counterparty rung of `route-composer`'s ladder, and
//! conservatively converted to blocks for the hub rung (dividing by the
//! MINIMUM block interval, rounding up — the fastest possible chain
//! needs the most blocks to cover the same seconds).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use adapter_btc::timelock::{minimum_safety_margin_seconds, ChainTimingBoundsV1};
use adapter_btc::types::BitcoinNetworkV1;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::{AssetId, ChainId, Digest32, FinalityPolicyV1};

/// Domain tag of [`ChainProfileV1::profile_digest`] (A3 pattern).
pub const CHAIN_PROFILE_DOMAIN: &[u8] = b"DOM-INTEROP/CHAIN-PROFILE/V1\0";

/// Upper bound of the allowed-asset list: profiles are reviewed by a
/// person; an unbounded list cannot be.
pub const MAX_ALLOWED_ASSETS: usize = 64;

/// The EVM mainnet chain id, excluded exactly as
/// `adapter-evm::EvmAdapterConfig::validate` excludes it.
pub const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;

/// Everything a profile can refuse, by name (I13).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProfileRefusal {
    /// Timing bounds refused by the M.8 arithmetic (zero or inverted
    /// block-interval bounds, or budget overflow).
    #[error("invalid timing bounds")]
    InvalidTimingBounds,
    /// Finality policy the terms layer would refuse
    /// (`min_confirmations == 0` or `max_reorg_depth < min_confirmations`).
    #[error("invalid finality policy")]
    InvalidFinality,
    /// `max_reorg_seconds` does not cover the finality policy's own
    /// tolerated reorg depth at the slowest block interval: the seconds
    /// budget the window trusts would be smaller than the reorg the
    /// profile itself admits.
    #[error("reorg budget below finality depth")]
    ReorgBudgetBelowFinalityDepth,
    /// EVM chain id 0, or 1: mainnet remains excluded (the adapter's own
    /// rule, kept here so a profile cannot even be written for it).
    #[error("mainnet excluded")]
    MainnetExcluded,
    /// The expected code hash is all-zero: an unpinned contract is not a
    /// profile, it is an invitation.
    #[error("unpinned code hash")]
    UnpinnedCodeHash,
    /// The allowed-asset list repeats an entry.
    #[error("duplicate asset")]
    DuplicateAsset,
    /// The allowed-asset list exceeds [`MAX_ALLOWED_ASSETS`].
    #[error("too many assets")]
    TooManyAssets,
    /// Checked arithmetic overflowed.
    #[error("overflow")]
    Overflow,
    /// Hash initialization failed (theoretical; named, never a panic — I14).
    #[error("hash initialization")]
    HashInitialization,
}

/// What kind of chain the profile describes, with the kind-specific
/// deployment facts the adapters need.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainKindV1 {
    /// An EVM chain running the audited condition-lock contracts.
    Evm {
        /// The EVM chain id (`EvmAdapterConfig.chain_id`). 0 and 1 refuse.
        evm_chain_id: u64,
        /// Deployed `ConditionLockV2` (native asset variant).
        native_lock_contract: [u8; 20],
        /// `keccak256` of the bytecode expected at the NATIVE contract
        /// (`EvmAdapterConfig.expected_code_hash`). Zero refuses.
        native_code_hash: [u8; 32],
        /// Deployed `ConditionLockERC20V2` with ITS OWN expected code
        /// hash, when token swaps are enabled. Two different contracts
        /// are two different bytecodes; one hash cannot pin both
        /// (audit finding AB-3).
        erc20_lock_contract: Option<([u8; 20], [u8; 32])>,
    },
    /// A Bitcoin network of the F5 registry. Mainnet does not exist in
    /// [`BitcoinNetworkV1`] (D-027) and therefore cannot be profiled.
    Bitcoin {
        /// The F5 network.
        network: BitcoinNetworkV1,
    },
}

/// One enabled chain: the explicit, validated, digest-committed facts
/// every layer above trusts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainProfileV1 {
    /// The 32-byte registry id (`LegTermsV1.chain_id`).
    pub chain_id: ChainId,
    /// The chain kind and its deployment facts.
    pub kind: ChainKindV1,
    /// The timing bounds the M.8 window inequality trusts.
    pub timing: ChainTimingBoundsV1,
    /// The finality policy the settlement legs consume.
    pub finality: FinalityPolicyV1,
    /// The chain's native asset registry id.
    pub native_asset: AssetId,
    /// The allowed non-native assets (e.g. the ERC-20 list), bounded.
    pub allowed_assets: Vec<AssetId>,
}

impl ChainProfileV1 {
    /// Validate every profile rule. Fail-closed: an invalid profile has
    /// no digest and must never reach an adapter or a composer.
    pub fn validate(&self) -> Result<(), ProfileRefusal> {
        // Timing bounds through the SAME arithmetic the M.8 validator
        // applies (self against self exercises exactly the bound checks
        // and the budget sum): reuse, never a second implementation.
        minimum_safety_margin_seconds(&self.timing, &self.timing)
            .map_err(|_| ProfileRefusal::InvalidTimingBounds)?;
        // The three budgets are what the composed margin FLOORS are
        // built from; a zero budget silently underestimates every floor
        // derived from this profile (audit finding AB-2).
        if self.timing.max_reorg_seconds == 0
            || self.timing.observation_seconds == 0
            || self.timing.broadcast_seconds == 0
        {
            return Err(ProfileRefusal::InvalidTimingBounds);
        }

        // The terms layer's own finality rule (SettlementTermsV1::validate).
        if self.finality.min_confirmations == 0
            || self.finality.max_reorg_depth < self.finality.min_confirmations
        {
            return Err(ProfileRefusal::InvalidFinality);
        }

        // Coherence between the two reorg statements this profile makes:
        // the SECONDS budget must cover the DEPTH the finality policy
        // tolerates, at the slowest admitted block interval.
        let depth_seconds = u64::from(self.finality.max_reorg_depth)
            .checked_mul(u64::from(self.timing.max_block_seconds))
            .ok_or(ProfileRefusal::Overflow)?;
        if u64::from(self.timing.max_reorg_seconds) < depth_seconds {
            return Err(ProfileRefusal::ReorgBudgetBelowFinalityDepth);
        }

        match self.kind {
            ChainKindV1::Evm {
                evm_chain_id,
                native_code_hash,
                erc20_lock_contract,
                ..
            } => {
                if evm_chain_id == 0 || evm_chain_id == ETHEREUM_MAINNET_CHAIN_ID {
                    return Err(ProfileRefusal::MainnetExcluded);
                }
                if native_code_hash == [0u8; 32] {
                    return Err(ProfileRefusal::UnpinnedCodeHash);
                }
                if let Some((_, erc20_hash)) = erc20_lock_contract {
                    if erc20_hash == [0u8; 32] {
                        return Err(ProfileRefusal::UnpinnedCodeHash);
                    }
                }
            }
            // Mainnet is unrepresentable in BitcoinNetworkV1 (D-027):
            // nothing further to refuse here by construction.
            ChainKindV1::Bitcoin { .. } => {}
        }

        if self.allowed_assets.len() > MAX_ALLOWED_ASSETS {
            return Err(ProfileRefusal::TooManyAssets);
        }
        for (i, a) in self.allowed_assets.iter().enumerate() {
            if *a == self.native_asset || self.allowed_assets[..i].contains(a) {
                return Err(ProfileRefusal::DuplicateAsset);
            }
        }
        Ok(())
    }

    /// Canonical bytes: fixed field order, integers big-endian, the
    /// asset list length-prefixed. Only a valid profile encodes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileRefusal> {
        self.validate()?;
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.chain_id.0);
        match self.kind {
            ChainKindV1::Evm {
                evm_chain_id,
                native_lock_contract,
                native_code_hash,
                erc20_lock_contract,
            } => {
                out.push(0x01);
                out.extend_from_slice(&evm_chain_id.to_be_bytes());
                out.extend_from_slice(&native_lock_contract);
                out.extend_from_slice(&native_code_hash);
                match erc20_lock_contract {
                    Some((c, h)) => {
                        out.push(0x01);
                        out.extend_from_slice(&c);
                        out.extend_from_slice(&h);
                    }
                    None => out.push(0x00),
                }
            }
            ChainKindV1::Bitcoin { network } => {
                out.push(0x02);
                out.push(network as u8);
            }
        }
        for v in [
            self.timing.min_block_seconds,
            self.timing.max_block_seconds,
            self.timing.max_reorg_seconds,
            self.timing.observation_seconds,
            self.timing.broadcast_seconds,
            self.finality.min_confirmations,
            self.finality.max_reorg_depth,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.extend_from_slice(&self.native_asset.0);
        out.extend_from_slice(&(self.allowed_assets.len() as u64).to_be_bytes());
        for a in &self.allowed_assets {
            out.extend_from_slice(&a.0);
        }
        Ok(out)
    }

    /// `BLAKE2b-256(domain || canonical_bytes)` — the digest a session
    /// pins so both parties provably priced the same chain facts.
    pub fn profile_digest(&self) -> Result<Digest32, ProfileRefusal> {
        let encoded = self.canonical_bytes()?;
        let mut h = Blake2bVar::new(32).map_err(|_| ProfileRefusal::HashInitialization)?;
        h.update(CHAIN_PROFILE_DOMAIN);
        h.update(&encoded);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out)
            .map_err(|_| ProfileRefusal::HashInitialization)?;
        Ok(out)
    }
}

/// The composed-route counterparty-rung margin FLOOR between two
/// profiled chains, in seconds: the M.8 additive rule
/// (`minimum_safety_margin_seconds`) applied to the two counterparty
/// chains' budgets — reused verbatim, never re-derived. A
/// `route-composer` `counterparty_margin` below this floor is unsound.
pub fn composed_counterparty_margin_floor_seconds(
    upstream: &ChainProfileV1,
    downstream: &ChainProfileV1,
) -> Result<u64, ProfileRefusal> {
    upstream.validate()?;
    downstream.validate()?;
    minimum_safety_margin_seconds(&upstream.timing, &downstream.timing)
        .map_err(|_| ProfileRefusal::InvalidTimingBounds)
}

/// The composed-route hub-rung margin FLOOR, in hub blocks: the hub's
/// own additive budget (its reorg + observation + broadcast, counted
/// twice — both settlements observe and react on the hub), divided by
/// the MINIMUM block interval and rounded up. Conservative on purpose:
/// the fastest the chain can run, the more blocks the same seconds
/// take. Lab rule, same standing as the additive M.8 margin.
pub fn composed_hub_margin_floor_blocks(hub: &ChainProfileV1) -> Result<u64, ProfileRefusal> {
    hub.validate()?;
    let seconds = minimum_safety_margin_seconds(&hub.timing, &hub.timing)
        .map_err(|_| ProfileRefusal::InvalidTimingBounds)?;
    let min_interval = u64::from(hub.timing.min_block_seconds);
    // ceil(seconds / min_interval); min_interval > 0 is guaranteed by
    // the bounds validation above.
    seconds
        .checked_add(min_interval - 1)
        .ok_or(ProfileRefusal::Overflow)
        .map(|s| s / min_interval)
}
