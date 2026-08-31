//! Public, secret-free Bitcoin actuator model.

use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use deployment_registry::ResolvedBitcoinDeploymentV1;

use crate::{BitcoinActuatorErrorV1, Result};

const SCOPE_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/SCOPE/V1\0";
const DEPLOYMENT_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/DEPLOYMENT/V1\0";
const INTENT_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/TX-INTENT/V1\0";
const INVARIANT_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/TX-INVARIANT/V1\0";
const CHAIN_IDENTITY_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/CHAIN-IDENTITY/V1\0";
const TERMINAL_LOCATOR_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/TERMINAL-LOCATOR/V1\0";
const FUNDING_LOCATOR_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/FUNDING-LOCATOR/V1\0";
const PORT_CALL_OUTCOME_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/PORT-CALL-OUTCOME/V1\0";
const ACTUATION_SCOPE_BYTES: usize = 554;
/// Exact byte length of a canonical durable port-call outcome.
pub const BITCOIN_PORT_CALL_OUTCOME_V1_BYTES: usize = 66;
const MAX_RAW_TRANSACTION_BYTES: usize = 4_000_000;
const MAX_SIGNET_CHALLENGE_BYTES: usize = 10_000;
const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;

/// Which composed-route leg the Bitcoin action belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinLegV1 {
    /// Upstream leg of the composed route.
    Upstream,
    /// Downstream leg of the composed route.
    Downstream,
}

impl BitcoinLegV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Upstream => 1,
            Self::Downstream => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Upstream),
            2 => Ok(Self::Downstream),
            _ => Err(BitcoinActuatorErrorV1::CorruptState),
        }
    }
}

/// Closed set of external Bitcoin actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinActionV1 {
    /// Wallet funding transaction, gated by an already durable refund.
    Funding,
    /// Cooperative adaptor claim transaction.
    Claim,
    /// CSV script-path refund transaction.
    Refund,
}

impl BitcoinActionV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Funding => 1,
            Self::Claim => 2,
            Self::Refund => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Funding),
            2 => Ok(Self::Claim),
            3 => Ok(Self::Refund),
            _ => Err(BitcoinActuatorErrorV1::CorruptState),
        }
    }

    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Claim | Self::Refund)
    }
}

/// Exact Bitcoin outpoint in internal txid byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinOutpointV1 {
    /// Transaction id in rust-bitcoin internal byte order.
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

/// Immutable fee-replacement policy for one exact transaction family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinFeeBumpPolicyV1 {
    /// Exact fee of generation zero.
    pub initial_fee_sat: u64,
    /// Maximum absolute fee across all generations.
    pub maximum_fee_sat: u64,
    /// Maximum authorized fee rate in satoshis per virtual byte.
    pub maximum_fee_rate_sat_vbyte: u64,
    /// Sole output whose value may decrease; scripts/order never change.
    pub change_vout: Option<u32>,
}

impl BitcoinFeeBumpPolicyV1 {
    pub(crate) fn validate(self, deployment_max_rate: u64) -> Result<()> {
        if self.initial_fee_sat == 0
            || self.maximum_fee_sat < self.initial_fee_sat
            || self.maximum_fee_rate_sat_vbyte == 0
            || self.maximum_fee_rate_sat_vbyte > deployment_max_rate
        {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        Ok(())
    }
}

/// Route/effect/action capability derived only from an authenticated registry.
///
/// The value is intentionally not `Clone`, `Copy`, or `Debug`. It contains no
/// secret, but keeping it linear makes accidental cross-dispatch reuse visible;
/// durable idempotency and fencing remain the final enforcement boundary.
pub struct BitcoinActuationScopeV1 {
    route_id: [u8; 32],
    effect_id: [u8; 32],
    leg: BitcoinLegV1,
    action: BitcoinActionV1,
    fence_epoch: u64,
    terms_digest: [u8; 32],
    registry_digest: [u8; 32],
    registry_epoch: u64,
    profile_digest: [u8; 32],
    asset_binding_digest: [u8; 32],
    chain_id: [u8; 32],
    deployment_digest: [u8; 32],
    network: BitcoinNetworkV1,
    genesis_hash: [u8; 32],
    signet_challenge_digest: [u8; 32],
    expected_txid: [u8; 32],
    intent_digest: [u8; 32],
    contract_outpoint: Option<BitcoinOutpointV1>,
    contract_amount_sat: u64,
    refund_record_digest: Option<[u8; 32]>,
    fee_policy: BitcoinFeeBumpPolicyV1,
    minimum_confirmations: u32,
    valid_until_ms: u64,
    scope_digest: [u8; 32],
}

/// Exact authenticated material used to mint one Bitcoin actuation scope.
///
/// Grouping these fields prevents a caller from silently omitting or
/// reordering a route, deployment, custody, fee, or expiry binding.
pub struct BitcoinActuationScopeAuthorizationV1<'a> {
    /// Threshold-resolved Bitcoin deployment selected for this route.
    pub deployment: &'a ResolvedBitcoinDeploymentV1,
    /// Stable route identity.
    pub route_id: [u8; 32],
    /// Stable outbox effect identity.
    pub effect_id: [u8; 32],
    /// Frozen route leg.
    pub leg: BitcoinLegV1,
    /// Exact authorized Bitcoin action.
    pub action: BitcoinActionV1,
    /// Route-supervisor fencing epoch.
    pub fence_epoch: u64,
    /// Frozen settlement-terms digest.
    pub terms_digest: [u8; 32],
    /// Exact transaction id authorized by the intent.
    pub expected_txid: [u8; 32],
    /// Exact action-intent digest.
    pub intent_digest: [u8; 32],
    /// Existing contract outpoint for a terminal action.
    pub contract_outpoint: Option<BitcoinOutpointV1>,
    /// Amount held by, or entering, the Bitcoin contract.
    pub contract_amount_sat: u64,
    /// Durable refund record required before funding.
    pub refund_record_digest: Option<[u8; 32]>,
    /// Bounded fee and replacement policy.
    pub fee_policy: BitcoinFeeBumpPolicyV1,
    /// Absolute authorization expiry.
    pub valid_until_ms: u64,
}

impl BitcoinActuationScopeV1 {
    /// Builds one capability from the exact threshold-authenticated Bitcoin
    /// deployment selected for the route.
    pub fn authorize(request: BitcoinActuationScopeAuthorizationV1<'_>) -> Result<Self> {
        let BitcoinActuationScopeAuthorizationV1 {
            deployment,
            route_id,
            effect_id,
            leg,
            action,
            fence_epoch,
            terms_digest,
            expected_txid,
            intent_digest,
            contract_outpoint,
            contract_amount_sat,
            refund_record_digest,
            fee_policy,
            valid_until_ms,
        } = request;
        deployment
            .profile()
            .validate()
            .map_err(|_| BitcoinActuatorErrorV1::InvalidScope)?;
        let network = match deployment.profile().kind {
            chain_profile::ChainKindV1::Bitcoin { network } => network,
            chain_profile::ChainKindV1::Evm { .. } => {
                return Err(BitcoinActuatorErrorV1::InvalidScope)
            }
        };
        let facts = deployment.deployment();
        fee_policy.validate(facts.max_fee_rate_sat_vbyte)?;
        let minimum_confirmations = deployment.profile().finality.min_confirmations;
        if route_id == [0; 32]
            || effect_id == [0; 32]
            || fence_epoch == 0
            || terms_digest == [0; 32]
            || deployment.registry_digest() == [0; 32]
            || deployment.registry_epoch() == 0
            || deployment.profile_digest() == [0; 32]
            || deployment.asset_binding_digest() == [0; 32]
            || deployment.profile().chain_id.0 == [0; 32]
            || facts.genesis_hash == [0; 32]
            || facts.signet_challenge.len() > MAX_SIGNET_CHALLENGE_BYTES
            || expected_txid == [0; 32]
            || intent_digest == [0; 32]
            || contract_amount_sat == 0
            || contract_amount_sat > MAX_MONEY_SAT
            || minimum_confirmations == 0
            || valid_until_ms == 0
            || (action.is_terminal() && contract_outpoint.is_none())
            || (action == BitcoinActionV1::Funding && contract_outpoint.is_some())
            || (action == BitcoinActionV1::Funding
                && match refund_record_digest {
                    Some(digest) => digest == [0; 32],
                    None => true,
                })
        {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        let signet_challenge_digest = deployment_component_digest(&facts.signet_challenge)?;
        let deployment_digest = resolved_deployment_digest(deployment)?;
        let mut value = Self {
            route_id,
            effect_id,
            leg,
            action,
            fence_epoch,
            terms_digest,
            registry_digest: deployment.registry_digest(),
            registry_epoch: deployment.registry_epoch(),
            profile_digest: deployment.profile_digest(),
            asset_binding_digest: deployment.asset_binding_digest(),
            chain_id: deployment.profile().chain_id.0,
            deployment_digest,
            network,
            genesis_hash: facts.genesis_hash,
            signet_challenge_digest,
            expected_txid,
            intent_digest,
            contract_outpoint,
            contract_amount_sat,
            refund_record_digest,
            fee_policy,
            minimum_confirmations,
            valid_until_ms,
            scope_digest: [0; 32],
        };
        value.scope_digest = digest(SCOPE_DOMAIN, &value.canonical_bytes_without_digest())?;
        Ok(value)
    }

    /// Stable route identity.
    pub const fn route_id(&self) -> [u8; 32] {
        self.route_id
    }

    /// Stable outbox effect identity.
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Frozen composed-route leg.
    pub const fn leg(&self) -> BitcoinLegV1 {
        self.leg
    }

    /// Exact authorized action.
    pub const fn action(&self) -> BitcoinActionV1 {
        self.action
    }

    /// Route-supervisor fencing epoch.
    pub const fn fence_epoch(&self) -> u64 {
        self.fence_epoch
    }

    /// Frozen settlement-terms digest.
    pub const fn terms_digest(&self) -> [u8; 32] {
        self.terms_digest
    }

    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.registry_digest
    }

    /// Monotonic epoch of the authenticated registry manifest.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Authenticated generic profile digest.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    /// Authenticated asset-binding digest selected by the registry.
    pub const fn asset_binding_digest(&self) -> [u8; 32] {
        self.asset_binding_digest
    }

    /// Authenticated logical chain identity from the resolved registry profile.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Authenticated Bitcoin deployment-facts digest.
    pub const fn deployment_digest(&self) -> [u8; 32] {
        self.deployment_digest
    }

    /// Expected transaction id in internal byte order.
    pub const fn expected_txid(&self) -> [u8; 32] {
        self.expected_txid
    }

    /// Exact transaction-intent commitment.
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    /// Exact contract outpoint for claim/refund.
    pub const fn contract_outpoint(&self) -> Option<BitcoinOutpointV1> {
        self.contract_outpoint
    }

    /// Exact contract amount in satoshis.
    pub const fn contract_amount_sat(&self) -> u64 {
        self.contract_amount_sat
    }

    /// Digest of the already durable refund for funding actions.
    pub const fn refund_record_digest(&self) -> Option<[u8; 32]> {
        self.refund_record_digest
    }

    /// Fee/replacement policy frozen into this authority.
    pub const fn fee_policy(&self) -> BitcoinFeeBumpPolicyV1 {
        self.fee_policy
    }

    /// Confirmations required by the authenticated chain profile.
    pub const fn minimum_confirmations(&self) -> u32 {
        self.minimum_confirmations
    }

    /// Capability expiry in Unix milliseconds.
    pub const fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }

    /// Canonical commitment to every scope field.
    pub const fn scope_digest(&self) -> [u8; 32] {
        self.scope_digest
    }

    pub(crate) const fn network(&self) -> BitcoinNetworkV1 {
        self.network
    }

    pub(crate) const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub(crate) const fn signet_challenge_digest(&self) -> [u8; 32] {
        self.signet_challenge_digest
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.canonical_bytes_without_digest();
        bytes.extend_from_slice(&self.scope_digest);
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ACTUATION_SCOPE_BYTES {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        let mut decoder = ScopeDecoder::new(bytes);
        let route_id = decoder.array_32()?;
        let effect_id = decoder.array_32()?;
        let leg = BitcoinLegV1::from_tag(decoder.u8()?)?;
        let action = BitcoinActionV1::from_tag(decoder.u8()?)?;
        let fence_epoch = decoder.u64()?;
        let terms_digest = decoder.array_32()?;
        let registry_digest = decoder.array_32()?;
        let registry_epoch = decoder.u64()?;
        let profile_digest = decoder.array_32()?;
        let asset_binding_digest = decoder.array_32()?;
        let chain_id = decoder.array_32()?;
        let deployment_digest = decoder.array_32()?;
        let network = BitcoinNetworkV1::from_u8(decoder.u8()?, "bitcoin_actuation_scope.network")
            .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
        let genesis_hash = decoder.array_32()?;
        let signet_challenge_digest = decoder.array_32()?;
        let expected_txid = decoder.array_32()?;
        let intent_digest = decoder.array_32()?;
        let contract_outpoint = match decoder.u8()? {
            0 => {
                decoder.require_zeroes(36)?;
                None
            }
            1 => Some(BitcoinOutpointV1 {
                txid: decoder.array_32()?,
                vout: decoder.u32()?,
            }),
            _ => return Err(BitcoinActuatorErrorV1::CorruptState),
        };
        let contract_amount_sat = decoder.u64()?;
        let refund_record_digest = match decoder.u8()? {
            0 => {
                decoder.require_zeroes(32)?;
                None
            }
            1 => Some(decoder.array_32()?),
            _ => return Err(BitcoinActuatorErrorV1::CorruptState),
        };
        let fee_policy = BitcoinFeeBumpPolicyV1 {
            initial_fee_sat: decoder.u64()?,
            maximum_fee_sat: decoder.u64()?,
            maximum_fee_rate_sat_vbyte: decoder.u64()?,
            change_vout: match decoder.u8()? {
                0 => {
                    decoder.require_zeroes(4)?;
                    None
                }
                1 => Some(decoder.u32()?),
                _ => return Err(BitcoinActuatorErrorV1::CorruptState),
            },
        };
        let minimum_confirmations = decoder.u32()?;
        let valid_until_ms = decoder.u64()?;
        let scope_digest = decoder.array_32()?;
        if !decoder.is_finished()
            || route_id == [0; 32]
            || effect_id == [0; 32]
            || fence_epoch == 0
            || terms_digest == [0; 32]
            || registry_digest == [0; 32]
            || registry_epoch == 0
            || profile_digest == [0; 32]
            || asset_binding_digest == [0; 32]
            || chain_id == [0; 32]
            || genesis_hash == [0; 32]
            || expected_txid == [0; 32]
            || intent_digest == [0; 32]
            || contract_amount_sat == 0
            || contract_amount_sat > MAX_MONEY_SAT
            || minimum_confirmations == 0
            || valid_until_ms == 0
            || (action.is_terminal() && contract_outpoint.is_none())
            || (action == BitcoinActionV1::Funding && contract_outpoint.is_some())
            || (action == BitcoinActionV1::Funding
                && match refund_record_digest {
                    Some(value) => value == [0; 32],
                    None => true,
                })
        {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        fee_policy
            .validate(u64::MAX)
            .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
        let value = Self {
            route_id,
            effect_id,
            leg,
            action,
            fence_epoch,
            terms_digest,
            registry_digest,
            registry_epoch,
            profile_digest,
            asset_binding_digest,
            chain_id,
            deployment_digest,
            network,
            genesis_hash,
            signet_challenge_digest,
            expected_txid,
            intent_digest,
            contract_outpoint,
            contract_amount_sat,
            refund_record_digest,
            fee_policy,
            minimum_confirmations,
            valid_until_ms,
            scope_digest,
        };
        if digest(SCOPE_DOMAIN, &value.canonical_bytes_without_digest())? != scope_digest
            || value.canonical_bytes() != bytes
        {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        Ok(value)
    }

    pub(crate) fn same_replacement_family(&self, other: &Self) -> bool {
        self.route_id == other.route_id
            && self.effect_id == other.effect_id
            && self.leg == other.leg
            && self.action == other.action
            && self.fence_epoch == other.fence_epoch
            && self.terms_digest == other.terms_digest
            && self.registry_digest == other.registry_digest
            && self.registry_epoch == other.registry_epoch
            && self.profile_digest == other.profile_digest
            && self.asset_binding_digest == other.asset_binding_digest
            && self.chain_id == other.chain_id
            && self.deployment_digest == other.deployment_digest
            && self.network == other.network
            && self.genesis_hash == other.genesis_hash
            && self.signet_challenge_digest == other.signet_challenge_digest
            && self.contract_outpoint == other.contract_outpoint
            && self.contract_amount_sat == other.contract_amount_sat
            && self.refund_record_digest == other.refund_record_digest
            && self.fee_policy == other.fee_policy
            && self.minimum_confirmations == other.minimum_confirmations
            && self.valid_until_ms == other.valid_until_ms
    }

    fn canonical_bytes_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(&self.route_id);
        bytes.extend_from_slice(&self.effect_id);
        bytes.push(self.leg.tag());
        bytes.push(self.action.tag());
        bytes.extend_from_slice(&self.fence_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.terms_digest);
        bytes.extend_from_slice(&self.registry_digest);
        bytes.extend_from_slice(&self.registry_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.profile_digest);
        bytes.extend_from_slice(&self.asset_binding_digest);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.deployment_digest);
        bytes.push(self.network as u8);
        bytes.extend_from_slice(&self.genesis_hash);
        bytes.extend_from_slice(&self.signet_challenge_digest);
        bytes.extend_from_slice(&self.expected_txid);
        bytes.extend_from_slice(&self.intent_digest);
        match self.contract_outpoint {
            Some(outpoint) => {
                bytes.push(1);
                bytes.extend_from_slice(&outpoint.txid);
                bytes.extend_from_slice(&outpoint.vout.to_be_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 36]);
            }
        }
        bytes.extend_from_slice(&self.contract_amount_sat.to_be_bytes());
        match self.refund_record_digest {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value);
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&[0; 32]);
            }
        }
        bytes.extend_from_slice(&self.fee_policy.initial_fee_sat.to_be_bytes());
        bytes.extend_from_slice(&self.fee_policy.maximum_fee_sat.to_be_bytes());
        bytes.extend_from_slice(&self.fee_policy.maximum_fee_rate_sat_vbyte.to_be_bytes());
        match self.fee_policy.change_vout {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(&0_u32.to_be_bytes());
            }
        }
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&self.valid_until_ms.to_be_bytes());
        bytes
    }
}

struct ScopeDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ScopeDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BitcoinActuatorErrorV1::CorruptState)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?,
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?,
        ))
    }

    fn array_32(&mut self) -> Result<[u8; 32]> {
        self.take(32)?
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::CorruptState)
    }

    fn require_zeroes(&mut self, length: usize) -> Result<()> {
        if self.take(length)?.iter().any(|value| *value != 0) {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        Ok(())
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Durable table holding an exact Bitcoin actuation effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinOperationKindV1 {
    /// Claim/refund bytes retained by the terminal-operation authority.
    Terminal,
    /// Opaque funding custody retained by the funding authority.
    Funding,
}

impl BitcoinOperationKindV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Terminal => 1,
            Self::Funding => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Terminal),
            2 => Ok(Self::Funding),
            _ => Err(BitcoinActuatorErrorV1::CorruptState),
        }
    }
}

/// Raw-free durable operation state, preserving terminal/funding separation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinDurableOperationViewV1 {
    /// Terminal claim/refund operation.
    Terminal(BitcoinOperationViewV1),
    /// Funding custody operation.
    Funding(BitcoinFundingCustodyViewV1),
}

/// Exact public locator for one durable Bitcoin custody row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinOperationLocatorV1 {
    pub(crate) kind: BitcoinOperationKindV1,
    pub(crate) effect_id: [u8; 32],
    pub(crate) scope_digest: [u8; 32],
    pub(crate) custody_locator: [u8; 32],
}

impl BitcoinOperationLocatorV1 {
    /// Durable terminal/funding table identity.
    pub const fn kind(&self) -> BitcoinOperationKindV1 {
        self.kind
    }

    /// Exact effect identity.
    pub const fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Commitment to the reopened canonical actuation scope.
    pub const fn scope_digest(&self) -> [u8; 32] {
        self.scope_digest
    }

    /// Domain-separated locator for the durable custody row.
    pub const fn custody_locator(&self) -> [u8; 32] {
        self.custody_locator
    }
}

/// Atomic, lease-scoped binding of an opaque scope to its durable public view.
///
/// The value deliberately has no `Clone`: callers can inspect the recovered
/// capability but cannot cheaply duplicate it into another dispatch path.
pub struct BitcoinOperationBindingViewV1 {
    pub(crate) scope: BitcoinActuationScopeV1,
    pub(crate) operation: BitcoinDurableOperationViewV1,
    pub(crate) locator: BitcoinOperationLocatorV1,
    pub(crate) chain_identity_digest: [u8; 32],
}

impl core::fmt::Debug for BitcoinOperationBindingViewV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BitcoinOperationBindingViewV1([redacted])")
    }
}

impl BitcoinOperationBindingViewV1 {
    /// Reopened opaque scope, authenticated against the durable row.
    pub const fn scope(&self) -> &BitcoinActuationScopeV1 {
        &self.scope
    }

    /// Raw-free durable operation state from the same read transaction.
    pub const fn operation(&self) -> BitcoinDurableOperationViewV1 {
        self.operation
    }

    /// Exact terminal/funding custody locator.
    pub const fn locator(&self) -> BitcoinOperationLocatorV1 {
        self.locator
    }

    /// Frozen composed-route leg.
    pub const fn leg(&self) -> BitcoinLegV1 {
        self.scope.leg
    }

    /// Explicit network/genesis/signet identity commitment.
    pub const fn chain_identity_digest(&self) -> [u8; 32] {
        self.chain_identity_digest
    }

    /// Authenticated logical chain identity from the registry profile.
    pub const fn chain_id(&self) -> [u8; 32] {
        self.scope.chain_id
    }

    /// Frozen settlement-terms commitment.
    pub const fn terms_digest(&self) -> [u8; 32] {
        self.scope.terms_digest
    }

    /// Authenticated registry commitment.
    pub const fn registry_digest(&self) -> [u8; 32] {
        self.scope.registry_digest
    }

    /// Authenticated profile commitment.
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.scope.profile_digest
    }

    /// Authenticated deployment commitment.
    pub const fn deployment_digest(&self) -> [u8; 32] {
        self.scope.deployment_digest
    }

    /// Reopened scope commitment.
    pub const fn scope_digest(&self) -> [u8; 32] {
        self.scope.scope_digest
    }

    /// Domain-separated durable custody locator.
    pub const fn custody_locator(&self) -> [u8; 32] {
        self.locator.custody_locator
    }
}

/// Coordinator child-port call class persisted in the idempotency journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinPortCallKindV1 {
    /// Externalization dispatch.
    Dispatch,
    /// Explicit externalization reconciliation.
    Reconciliation,
    /// Stable chain/finality observation.
    Observation,
}

impl BitcoinPortCallKindV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Dispatch => 1,
            Self::Reconciliation => 2,
            Self::Observation => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Dispatch),
            2 => Ok(Self::Reconciliation),
            3 => Ok(Self::Observation),
            _ => Err(BitcoinActuatorErrorV1::CorruptState),
        }
    }
}

/// Secret-free stable result bytes retained before a child-port call returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinPortCallOutcomeV1 {
    /// Exact operation crossed, or had already crossed, the external boundary.
    Externalized {
        /// Stable evidence for externalization.
        evidence_digest: [u8; 32],
        /// Stable evidence for the first exposure, when separately known.
        first_exposure_evidence_digest: Option<[u8; 32]>,
    },
    /// Retry is safe because externalization has not happened.
    RetryableBeforeExternalization {
        /// Stable public evidence.
        evidence_digest: [u8; 32],
    },
    /// Externalization cannot be determined safely.
    Unknown {
        /// Stable public evidence.
        evidence_digest: [u8; 32],
    },
    /// Reconciliation proved that externalization did not happen.
    ProvenNotExternalized {
        /// Stable public evidence.
        evidence_digest: [u8; 32],
    },
    /// Observation is not yet final.
    Pending {
        /// Stable public evidence.
        evidence_digest: [u8; 32],
    },
    /// Observation reached stable finality.
    Final {
        /// Stable public finality evidence.
        evidence_digest: [u8; 32],
    },
    /// Previously reported finality was invalidated.
    FinalityInvalidated {
        /// Evidence commitment returned by the prior final observation.
        prior_finality_evidence_digest: [u8; 32],
        /// Stable evidence for invalidation/reorganization.
        reorg_evidence_digest: [u8; 32],
    },
}

impl BitcoinPortCallOutcomeV1 {
    /// Canonical bytes replayed exactly after restart.
    pub fn canonical_bytes(&self) -> [u8; BITCOIN_PORT_CALL_OUTCOME_V1_BYTES] {
        let (tag, primary, secondary) = match *self {
            Self::Externalized {
                evidence_digest,
                first_exposure_evidence_digest,
            } => (1, evidence_digest, first_exposure_evidence_digest),
            Self::RetryableBeforeExternalization { evidence_digest } => (2, evidence_digest, None),
            Self::Unknown { evidence_digest } => (3, evidence_digest, None),
            Self::ProvenNotExternalized { evidence_digest } => (4, evidence_digest, None),
            Self::Pending { evidence_digest } => (5, evidence_digest, None),
            Self::Final { evidence_digest } => (6, evidence_digest, None),
            Self::FinalityInvalidated {
                prior_finality_evidence_digest,
                reorg_evidence_digest,
            } => (
                7,
                prior_finality_evidence_digest,
                Some(reorg_evidence_digest),
            ),
        };
        let mut bytes = [0_u8; BITCOIN_PORT_CALL_OUTCOME_V1_BYTES];
        bytes[0] = tag;
        bytes[1..33].copy_from_slice(&primary);
        if let Some(secondary) = secondary {
            bytes[33] = 1;
            bytes[34..].copy_from_slice(&secondary);
        }
        bytes
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BITCOIN_PORT_CALL_OUTCOME_V1_BYTES {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        let primary: [u8; 32] = bytes[1..33]
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
        let secondary: [u8; 32] = bytes[34..66]
            .try_into()
            .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
        if primary == [0; 32] || !matches!(bytes[33], 0 | 1) {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        let value = match (bytes[0], bytes[33]) {
            (1, 0) if secondary == [0; 32] => Self::Externalized {
                evidence_digest: primary,
                first_exposure_evidence_digest: None,
            },
            (1, 1) if secondary != [0; 32] => Self::Externalized {
                evidence_digest: primary,
                first_exposure_evidence_digest: Some(secondary),
            },
            (2, 0) if secondary == [0; 32] => Self::RetryableBeforeExternalization {
                evidence_digest: primary,
            },
            (3, 0) if secondary == [0; 32] => Self::Unknown {
                evidence_digest: primary,
            },
            (4, 0) if secondary == [0; 32] => Self::ProvenNotExternalized {
                evidence_digest: primary,
            },
            (5, 0) if secondary == [0; 32] => Self::Pending {
                evidence_digest: primary,
            },
            (6, 0) if secondary == [0; 32] => Self::Final {
                evidence_digest: primary,
            },
            (7, 1) if secondary != [0; 32] => Self::FinalityInvalidated {
                prior_finality_evidence_digest: primary,
                reorg_evidence_digest: secondary,
            },
            _ => return Err(BitcoinActuatorErrorV1::CorruptState),
        };
        if value.canonical_bytes() != bytes {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        Ok(value)
    }

    pub(crate) fn validate_for(self, kind: BitcoinPortCallKindV1) -> Result<()> {
        let valid = matches!(
            (kind, self),
            (
                BitcoinPortCallKindV1::Dispatch,
                Self::Externalized { .. }
                    | Self::RetryableBeforeExternalization { .. }
                    | Self::Unknown { .. }
            ) | (
                BitcoinPortCallKindV1::Reconciliation,
                Self::Externalized { .. }
                    | Self::ProvenNotExternalized { .. }
                    | Self::Unknown { .. }
            ) | (
                BitcoinPortCallKindV1::Observation,
                Self::Pending { .. } | Self::Final { .. } | Self::FinalityInvalidated { .. }
            )
        );
        if !valid {
            return Err(BitcoinActuatorErrorV1::InvalidState);
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        digest(PORT_CALL_OUTCOME_DOMAIN, &self.canonical_bytes())
    }
}

/// Immutable identity of one coordinator attempt and exact child-port request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinPortCallKeyV1 {
    pub(crate) call_kind: BitcoinPortCallKindV1,
    pub(crate) coordinator_attempt_id: [u8; 32],
    pub(crate) request_digest: [u8; 32],
    pub(crate) locator: BitcoinOperationLocatorV1,
}

impl BitcoinPortCallKeyV1 {
    /// Binds an exact coordinator attempt and request to one atomic operation binding.
    pub fn new(
        call_kind: BitcoinPortCallKindV1,
        coordinator_attempt_id: [u8; 32],
        request_digest: [u8; 32],
        binding: &BitcoinOperationBindingViewV1,
    ) -> Result<Self> {
        if coordinator_attempt_id == [0; 32] || request_digest == [0; 32] {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        Ok(Self {
            call_kind,
            coordinator_attempt_id,
            request_digest,
            locator: binding.locator,
        })
    }

    /// Port call class.
    pub const fn call_kind(&self) -> BitcoinPortCallKindV1 {
        self.call_kind
    }

    /// Exact coordinator attempt identity.
    pub const fn coordinator_attempt_id(&self) -> [u8; 32] {
        self.coordinator_attempt_id
    }

    /// Digest of the exact canonical child-port request.
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Exact durable operation locator.
    pub const fn locator(&self) -> BitcoinOperationLocatorV1 {
        self.locator
    }
}

/// Result of opening an idempotent durable port-call journal slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinPortCallJournalStatusV1 {
    /// Attempt is durably reserved but has not returned a public outcome.
    Pending,
    /// Exact stable outcome was already durably committed.
    Committed(BitcoinPortCallOutcomeV1),
}

pub(crate) fn chain_identity_digest(scope: &BitcoinActuationScopeV1) -> Result<[u8; 32]> {
    let mut bytes = Vec::with_capacity(65);
    bytes.push(scope.network as u8);
    bytes.extend_from_slice(&scope.genesis_hash);
    bytes.extend_from_slice(&scope.signet_challenge_digest);
    digest(CHAIN_IDENTITY_DOMAIN, &bytes)
}

pub(crate) fn terminal_custody_locator(
    scope_digest: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
    intent_digest: [u8; 32],
    invariant_digest: [u8; 32],
) -> Result<[u8; 32]> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(&scope_digest);
    bytes.extend_from_slice(&txid);
    bytes.extend_from_slice(&wtxid);
    bytes.extend_from_slice(&intent_digest);
    bytes.extend_from_slice(&invariant_digest);
    digest(TERMINAL_LOCATOR_DOMAIN, &bytes)
}

pub(crate) fn funding_custody_locator(
    scope_digest: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
    refund_record_digest: [u8; 32],
    custody_digest: [u8; 32],
) -> Result<[u8; 32]> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(&scope_digest);
    bytes.extend_from_slice(&txid);
    bytes.extend_from_slice(&wtxid);
    bytes.extend_from_slice(&refund_record_digest);
    bytes.extend_from_slice(&custody_digest);
    digest(FUNDING_LOCATOR_DOMAIN, &bytes)
}

/// Exact canonical transaction bytes held for external custody.
///
/// This value deliberately has no `Clone` or `Debug`; a claim signature may
/// reveal the adaptor scalar once published.
pub struct ExactBitcoinTransactionV1 {
    pub(crate) transaction: Transaction,
    pub(crate) raw: Vec<u8>,
    pub(crate) txid: [u8; 32],
    pub(crate) wtxid: [u8; 32],
    pub(crate) intent_digest: [u8; 32],
    pub(crate) invariant_digest: [u8; 32],
}

impl ExactBitcoinTransactionV1 {
    /// Strictly imports one canonical witness-bearing Bitcoin transaction.
    pub fn from_consensus_bytes(raw: Vec<u8>) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_RAW_TRANSACTION_BYTES {
            return Err(BitcoinActuatorErrorV1::InvalidTransaction);
        }
        let transaction: Transaction =
            deserialize(&raw).map_err(|_| BitcoinActuatorErrorV1::InvalidTransaction)?;
        if serialize(&transaction) != raw
            || transaction.input.is_empty()
            || transaction.output.is_empty()
            || transaction
                .output
                .iter()
                .any(|output| output.value.to_sat() > MAX_MONEY_SAT)
        {
            return Err(BitcoinActuatorErrorV1::InvalidTransaction);
        }
        let txid = transaction.compute_txid().to_raw_hash().to_byte_array();
        let wtxid = transaction.compute_wtxid().to_raw_hash().to_byte_array();
        let intent_digest = digest(INTENT_DOMAIN, &raw)?;
        let invariant_digest = transaction_invariant_digest(&transaction)?;
        Ok(Self {
            transaction,
            raw,
            txid,
            wtxid,
            intent_digest,
            invariant_digest,
        })
    }

    /// Transaction id in internal byte order.
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Witness transaction id in internal byte order.
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    /// Commitment to the exact witness-bearing bytes.
    pub const fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }

    /// Commitment to protected version/input/output/script/locktime/sequence facts.
    pub const fn invariant_digest(&self) -> [u8; 32] {
        self.invariant_digest
    }

    /// Consensus byte length; bytes themselves remain external-custody data.
    pub fn byte_len(&self) -> usize {
        self.raw.len()
    }

    /// Checked sum of every output value, used to authenticate the exact fee
    /// of a retained terminal transaction without exposing raw bytes.
    pub fn output_value_sat(&self) -> Result<u64> {
        self.transaction
            .output
            .iter()
            .try_fold(0_u64, |sum, output| {
                sum.checked_add(output.value.to_sat())
                    .ok_or(BitcoinActuatorErrorV1::InvalidTransaction)
            })
    }
}

/// Durable stage of one exact Bitcoin effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinOperationStageV1 {
    /// Exact raw bytes are durable and have never crossed the RPC boundary.
    Prepared,
    /// A send intent was durably committed before the RPC call.
    SendAttempted,
    /// The node acknowledged or already knew the exact transaction.
    BroadcastAcknowledged,
    /// The exact bytes were observed in the mempool.
    MempoolObserved,
    /// The exact bytes were observed in a canonical block below finality.
    Confirmed,
    /// Required finality was observed for the exact bytes.
    Final,
    /// Earlier confirmation was invalidated or the post-send state is absent.
    Ambiguous,
}

impl BitcoinOperationStageV1 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::SendAttempted => 2,
            Self::BroadcastAcknowledged => 3,
            Self::MempoolObserved => 4,
            Self::Confirmed => 5,
            Self::Final => 6,
            Self::Ambiguous => 7,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::SendAttempted),
            3 => Ok(Self::BroadcastAcknowledged),
            4 => Ok(Self::MempoolObserved),
            5 => Ok(Self::Confirmed),
            6 => Ok(Self::Final),
            7 => Ok(Self::Ambiguous),
            _ => Err(BitcoinActuatorErrorV1::CorruptState),
        }
    }
}

/// Public, raw-free view of a durable terminal transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinOperationViewV1 {
    /// Route identity.
    pub route_id: [u8; 32],
    /// Effect identity.
    pub effect_id: [u8; 32],
    /// Authorized action.
    pub action: BitcoinActionV1,
    /// Fencing epoch currently owning the row.
    pub fence_epoch: u64,
    /// Active transaction id.
    pub txid: [u8; 32],
    /// Commitment to active exact bytes.
    pub intent_digest: [u8; 32],
    /// Active replacement generation.
    pub generation: u32,
    /// Number of persist-before-send attempts.
    pub send_attempts: u32,
    /// Current durable lifecycle stage.
    pub stage: BitcoinOperationStageV1,
    /// Last exact canonical confirmation count.
    pub confirmations: u32,
    /// Canonical block currently carrying the exact transaction, when any.
    ///
    /// `None` is a real state: prepared, mempool, absent and reorg-invalidated
    /// rows do not have a canonical block.  A zero digest is never used as a
    /// second spelling of absence.
    pub block_hash: Option<[u8; 32]>,
    /// Canonical height currently carrying the exact transaction, when any.
    ///
    /// This is optional rather than sentinel-encoded; height zero remains a
    /// representable height and never means "not confirmed".
    pub block_height: Option<u64>,
    /// Durable evidence commitment produced by the most recent reconciliation.
    ///
    /// Reads do not perform RPC or advance the actuator clock; this is the
    /// commitment retained by the last successful state transition.
    pub evidence_digest: Option<[u8; 32]>,
}

/// Public, raw-free view of opaque `btc-live` funding custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinFundingCustodyViewV1 {
    /// Route identity.
    pub route_id: [u8; 32],
    /// Effect identity.
    pub effect_id: [u8; 32],
    /// Funding transaction id.
    pub txid: [u8; 32],
    /// Digest of the exact durable refund record.
    pub refund_record_digest: [u8; 32],
    /// Digest of the payload-free external custody commitment.
    pub custody_digest: [u8; 32],
    /// Fencing epoch currently owning the row.
    pub fence_epoch: u64,
    /// Number of persist-before-send attempts.
    pub send_attempts: u32,
    /// Current lifecycle stage.
    pub stage: BitcoinOperationStageV1,
    /// Last exact canonical confirmation count.
    pub confirmations: u32,
    /// Canonical block currently carrying the funding transaction, when any.
    pub block_hash: Option<[u8; 32]>,
    /// Canonical height currently carrying the funding transaction, when any.
    pub block_height: Option<u64>,
    /// Durable evidence commitment produced by the most recent reconciliation.
    pub evidence_digest: Option<[u8; 32]>,
}

/// Read-only lease status that never exposes the retained owner identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinStorageLeaseStatusV1 {
    pub(crate) fence_epoch: u64,
    pub(crate) expires_at_ms: u64,
}

impl BitcoinStorageLeaseStatusV1 {
    /// Current monotonic fencing epoch.
    pub const fn fence_epoch(&self) -> u64 {
        self.fence_epoch
    }

    /// Lease expiry in Unix milliseconds.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

/// Result of an explicit mempool/canonical-chain reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinReconciliationV1 {
    /// Exact bytes were not found and no send was ever attempted.
    ProvenNotExternalized,
    /// Exact bytes are currently in the mempool.
    ExactMempool,
    /// Exact bytes are canonical but not yet final.
    ExactConfirmed {
        /// Current confirmation count.
        confirmations: u32,
        /// Stable canonical height of the containing block.
        block_height: u64,
    },
    /// Exact bytes reached authenticated finality.
    ExactFinal {
        /// Current confirmation count.
        confirmations: u32,
        /// Stable canonical height of the containing block.
        block_height: u64,
    },
    /// A post-send absence or reorg cannot prove non-externalization.
    Ambiguous,
}

/// Public receipt proving that the exact committed transaction crossed the RPC boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinBroadcastReceiptV1 {
    /// Effect identity.
    pub effect_id: [u8; 32],
    /// Exact transaction id.
    pub txid: [u8; 32],
    /// Exact-byte commitment persisted before send.
    pub intent_digest: [u8; 32],
    /// Whether the node already knew the exact transaction.
    pub already_known: bool,
    /// Persist-before-send attempt number.
    pub attempt: u32,
}

pub(crate) fn validate_terminal_transaction(
    scope: &BitcoinActuationScopeV1,
    exact: &ExactBitcoinTransactionV1,
) -> Result<()> {
    if !scope.action.is_terminal()
        || scope.expected_txid != exact.txid
        || scope.intent_digest != exact.intent_digest
        || exact.transaction.input.len() != 1
    {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    let expected = scope
        .contract_outpoint
        .ok_or(BitcoinActuatorErrorV1::InvalidScope)?;
    let input = &exact.transaction.input[0];
    if input.previous_output.txid.to_raw_hash().to_byte_array() != expected.txid
        || input.previous_output.vout != expected.vout
    {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    let output_sum = exact
        .transaction
        .output
        .iter()
        .try_fold(0_u64, |sum, output| {
            sum.checked_add(output.value.to_sat())
                .ok_or(BitcoinActuatorErrorV1::InvalidTransaction)
        })?;
    let fee = scope
        .contract_amount_sat
        .checked_sub(output_sum)
        .ok_or(BitcoinActuatorErrorV1::TransactionMismatch)?;
    if fee != scope.fee_policy.initial_fee_sat {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    if scope.action == BitcoinActionV1::Claim && scope.fee_policy.change_vout.is_some() {
        return Err(BitcoinActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

pub(crate) fn validate_replacement(
    previous: &Transaction,
    replacement: &Transaction,
    previous_fee_sat: u64,
    policy: BitcoinFeeBumpPolicyV1,
) -> Result<u64> {
    if previous.version != replacement.version
        || previous.lock_time != replacement.lock_time
        || previous.input.len() != replacement.input.len()
        || previous.output.len() != replacement.output.len()
        || policy.change_vout.is_none()
    {
        return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
    }
    for (old, new) in previous.input.iter().zip(&replacement.input) {
        if old.previous_output != new.previous_output
            || old.sequence != new.sequence
            || old.script_sig != new.script_sig
        {
            return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
        }
    }
    let change_index = usize::try_from(
        policy
            .change_vout
            .ok_or(BitcoinActuatorErrorV1::UnsafeReplacement)?,
    )
    .map_err(|_| BitcoinActuatorErrorV1::UnsafeReplacement)?;
    if change_index >= previous.output.len() {
        return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
    }
    let mut reduction = 0_u64;
    for (index, (old, new)) in previous.output.iter().zip(&replacement.output).enumerate() {
        if old.script_pubkey != new.script_pubkey {
            return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
        }
        if index == change_index {
            reduction = old
                .value
                .to_sat()
                .checked_sub(new.value.to_sat())
                .filter(|value| *value > 0)
                .ok_or(BitcoinActuatorErrorV1::UnsafeReplacement)?;
        } else if old.value != new.value {
            return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
        }
    }
    let new_fee = previous_fee_sat
        .checked_add(reduction)
        .ok_or(BitcoinActuatorErrorV1::UnsafeReplacement)?;
    let vbytes = replacement.vsize() as u64;
    let fee_rate = new_fee
        .checked_add(vbytes.saturating_sub(1))
        .and_then(|value| value.checked_div(vbytes))
        .ok_or(BitcoinActuatorErrorV1::UnsafeReplacement)?;
    if new_fee > policy.maximum_fee_sat || fee_rate > policy.maximum_fee_rate_sat_vbyte {
        return Err(BitcoinActuatorErrorV1::UnsafeReplacement);
    }
    Ok(new_fee)
}

pub(crate) fn transaction_invariant_digest(transaction: &Transaction) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&transaction.version.0.to_be_bytes());
    bytes.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_be_bytes());
    bytes.extend_from_slice(
        &u32::try_from(transaction.input.len())
            .map_err(|_| BitcoinActuatorErrorV1::InvalidTransaction)?
            .to_be_bytes(),
    );
    for input in &transaction.input {
        bytes.extend_from_slice(&input.previous_output.txid.to_raw_hash().to_byte_array());
        bytes.extend_from_slice(&input.previous_output.vout.to_be_bytes());
        bytes.extend_from_slice(&input.sequence.to_consensus_u32().to_be_bytes());
        put_bytes(&mut bytes, input.script_sig.as_bytes())?;
    }
    bytes.extend_from_slice(
        &u32::try_from(transaction.output.len())
            .map_err(|_| BitcoinActuatorErrorV1::InvalidTransaction)?
            .to_be_bytes(),
    );
    for output in &transaction.output {
        bytes.extend_from_slice(&output.value.to_sat().to_be_bytes());
        put_bytes(&mut bytes, output.script_pubkey.as_bytes())?;
    }
    digest(INVARIANT_DOMAIN, &bytes)
}

pub(crate) fn digest(domain: &[u8], payload: &[u8]) -> Result<[u8; 32]> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
    hasher.update(domain);
    hasher.update(payload);
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| BitcoinActuatorErrorV1::CorruptState)?;
    Ok(output)
}

pub(crate) fn deployment_component_digest(payload: &[u8]) -> Result<[u8; 32]> {
    adapter_btc_live::bitcoin_signet_challenge_digest_v1(payload)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidScope)
}

pub(crate) fn resolved_deployment_digest(
    deployment: &ResolvedBitcoinDeploymentV1,
) -> Result<[u8; 32]> {
    let facts = deployment.deployment();
    let mut bytes = Vec::with_capacity(32 + facts.signet_challenge.len() + 24);
    bytes.extend_from_slice(&facts.genesis_hash);
    bytes.extend_from_slice(&facts.signet_challenge);
    bytes.extend_from_slice(&facts.max_fee_rate_sat_vbyte.to_be_bytes());
    bytes.extend_from_slice(&facts.min_relay_fee_sat_kvb.to_be_bytes());
    digest(DEPLOYMENT_DOMAIN, &bytes)
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| BitcoinActuatorErrorV1::InvalidTransaction)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod durable_binding_tests {
    use super::*;

    #[test]
    fn funding_and_terminal_locators_are_domain_separated() -> Result<()> {
        let facts = ([1; 32], [2; 32], [3; 32], [4; 32], [5; 32]);
        let terminal = terminal_custody_locator(facts.0, facts.1, facts.2, facts.3, facts.4)?;
        let funding = funding_custody_locator(facts.0, facts.1, facts.2, facts.3, facts.4)?;
        assert_ne!(terminal, funding);
        assert_ne!(terminal, [0; 32]);
        assert_ne!(funding, [0; 32]);
        Ok(())
    }

    #[test]
    fn port_outcome_codec_rejects_zero_trailing_and_noncanonical_bytes() -> Result<()> {
        let canonical = BitcoinPortCallOutcomeV1::Final {
            evidence_digest: [7; 32],
        }
        .canonical_bytes();
        assert_eq!(
            BitcoinPortCallOutcomeV1::from_canonical_bytes(&canonical)?.canonical_bytes(),
            canonical
        );
        let mut zero = canonical;
        zero[1..33].fill(0);
        assert!(BitcoinPortCallOutcomeV1::from_canonical_bytes(&zero).is_err());
        let mut noncanonical = canonical;
        noncanonical[65] = 1;
        assert!(BitcoinPortCallOutcomeV1::from_canonical_bytes(&noncanonical).is_err());
        let mut trailing = canonical.to_vec();
        trailing.push(0);
        assert!(BitcoinPortCallOutcomeV1::from_canonical_bytes(&trailing).is_err());

        let externalized = BitcoinPortCallOutcomeV1::Externalized {
            evidence_digest: [8; 32],
            first_exposure_evidence_digest: Some([9; 32]),
        };
        assert!(externalized
            .validate_for(BitcoinPortCallKindV1::Dispatch)
            .is_ok());
        assert!(externalized
            .validate_for(BitcoinPortCallKindV1::Reconciliation)
            .is_ok());
        assert!(externalized
            .validate_for(BitcoinPortCallKindV1::Observation)
            .is_err());
        assert!(BitcoinPortCallOutcomeV1::Pending {
            evidence_digest: [10; 32]
        }
        .validate_for(BitcoinPortCallKindV1::Observation)
        .is_ok());
        Ok(())
    }
}
