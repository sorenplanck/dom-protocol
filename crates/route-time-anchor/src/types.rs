use adapter_btc::timelock::{minimum_safety_margin_seconds, ChainTimingBoundsV1};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chain_profile::ChainKindV1;
use deployment_registry::{
    ChainDeploymentV1, DomNetworkV1, RegistryManifestV1, ResolvedRegistryV1,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{ChainId, Digest32, FinalityPolicyV1, LockMechanism, TimelockSpec};

use crate::codec::{decode_evidence_v2, decode_policy_v2, encode_evidence_v2, encode_policy_v2};
use crate::{
    Result, RouteTimeAnchorErrorV2, ROUTE_TIME_EVIDENCE_DOMAIN_V2, ROUTE_TIME_LADDER_DOMAIN_V2,
    ROUTE_TIME_POLICY_DOMAIN_V2, ROUTE_TIME_SCOPE_DOMAIN_V2,
};

const DOM_PROFILE_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/DOM-PROFILE/V1\0";

/// Maximum number of keys accepted by one time-authority threshold set.
pub const MAX_TIME_ANCHOR_AUTHORITIES_V2: usize = 16;
/// Bitcoin MTP uses eleven blocks and therefore spans ten block intervals.
pub const BTC_MTP_SAMPLE_INTERVALS_V2: u64 = 10;

/// Symmetric uncertainty band, in seconds, between the Solana cluster clock
/// (`Clock::unix_timestamp`, a stake-weighted vote estimate) and wall time.
///
/// The bank bounds the clock's drift rate but not its accumulated offset, and
/// the cluster has historically run tens of minutes behind wall time during
/// degraded periods. One hour covers every observed excursion with margin;
/// the cost of the conservatism is only that a route's legs must be spaced
/// further apart, never that a deadline fires earlier than proven.
pub const SOLANA_CLOCK_DRIFT_SECONDS_V2: u64 = 3_600;

/// Fixed role of one checkpoint in a three-chain composed route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CheckpointRoleV2 {
    /// Shared DOM hub checkpoint used by both DOM deadlines.
    Hub = 1,
    /// Counterparty chain of the upstream settlement.
    UpstreamCounterparty = 2,
    /// Counterparty chain of the downstream settlement.
    DownstreamCounterparty = 3,
}

/// Native clock whose authenticated checkpoint is being used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockKindV2 {
    /// Absolute DOM height projected with registry-signed block bounds.
    DomHeight = 1,
    /// Absolute EVM timestamp; checkpoint evidence supplies freshness/finality.
    EvmTimestamp = 2,
    /// Bitcoin height or BIP68 512-second MTP units.
    Bitcoin = 3,
    /// Monero block height. Absolute height is the only clock the XMR leg
    /// offers that an observer can evaluate deterministically, so it is the
    /// only one admitted here.
    Monero = 4,
    /// Solana cluster timestamp. Unlike an EVM timestamp it is an estimate,
    /// not a consensus-checked value, so its projection carries the
    /// [`SOLANA_CLOCK_DRIFT_SECONDS_V2`] band on both sides instead of the
    /// exact interval EVM gets.
    Solana = 5,
}

/// Exact authenticated facts a checkpoint must reproduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointBindingV2 {
    pub(crate) role: CheckpointRoleV2,
    pub(crate) clock_kind: ClockKindV2,
    pub(crate) chain_id: ChainId,
    pub(crate) genesis_hash: Digest32,
    pub(crate) profile_digest: Digest32,
    pub(crate) timing: ChainTimingBoundsV1,
    pub(crate) finality: FinalityPolicyV1,
}

impl CheckpointBindingV2 {
    /// Fixed route role of this checkpoint.
    pub const fn role(&self) -> CheckpointRoleV2 {
        self.role
    }

    /// Native clock selected from authenticated chain kind and terms.
    pub const fn clock_kind(&self) -> ClockKindV2 {
        self.clock_kind
    }

    /// Registry chain identifier.
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Authenticated chain genesis hash.
    pub const fn genesis_hash(&self) -> Digest32 {
        self.genesis_hash
    }

    /// Digest of the complete timing/finality/deployment profile.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }

    /// Registry-authenticated conservative block-time bounds.
    pub const fn timing(&self) -> ChainTimingBoundsV1 {
        self.timing
    }

    /// Registry-authenticated finality policy.
    pub const fn finality(&self) -> FinalityPolicyV1 {
        self.finality
    }
}

/// Signed policy limits applied in addition to registry timing bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteTimePolicyLimitsV2 {
    /// First trusted UNIX second at which this route policy is valid.
    pub valid_from_seconds: u64,
    /// First trusted UNIX second at which this route policy is invalid.
    pub expires_at_seconds: u64,
    /// Maximum age of one signed checkpoint revalidation.
    pub max_evidence_age_seconds: u64,
    /// Maximum width of an attested anchor-to-wall-clock interval.
    pub max_anchor_interval_width_seconds: u64,
    /// Maximum permitted lag from the interval's upper endpoint to observation.
    pub max_anchor_time_skew_seconds: u64,
    /// Maximum permitted anchor time ahead of signed observation time.
    pub max_future_skew_seconds: u64,
    /// Maximum signed delay from the checkpoint to a confirmed upstream
    /// counterparty funding anchor. Runtime must abort funding after it.
    pub max_upstream_funding_anchor_delay_seconds: u64,
    /// Maximum signed delay from the checkpoint to a confirmed downstream
    /// counterparty funding anchor. Runtime must abort funding after it.
    pub max_downstream_funding_anchor_delay_seconds: u64,
    /// Worst-case DOM-rung safety margin, expressed in seconds.
    pub hub_margin_seconds: u64,
    /// Worst-case counterparty-rung safety margin, expressed in seconds.
    pub counterparty_margin_seconds: u64,
}

/// Static route-scoped policy reconstructed from an authenticated registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTimePolicyV2 {
    pub(crate) network_id: Digest32,
    pub(crate) registry_digest: Digest32,
    pub(crate) registry_epoch: u64,
    pub(crate) upstream_terms_hash: Digest32,
    pub(crate) downstream_terms_hash: Digest32,
    pub(crate) route_scope_digest: Digest32,
    pub(crate) limits: RouteTimePolicyLimitsV2,
    pub(crate) checkpoints: [CheckpointBindingV2; 3],
}

impl RouteTimePolicyV2 {
    /// Reconstructs a policy only from registry-authenticated profiles and the
    /// exact two settlement terms. Public mainnet DOM is refused explicitly.
    pub fn from_registry(
        registry: &ResolvedRegistryV1,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
        limits: RouteTimePolicyLimitsV2,
    ) -> Result<Self> {
        upstream
            .validate()
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
        downstream
            .validate()
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
        if upstream.dom_leg.chain_id != downstream.dom_leg.chain_id
            || upstream.dom_leg.asset_id != downstream.dom_leg.asset_id
            || upstream.dom_leg.adapter_profile_hash != downstream.dom_leg.adapter_profile_hash
            || upstream.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
            || downstream.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
            || !matches!(upstream.dom_leg.deadline, TimelockSpec::BlockHeight { .. })
            || !matches!(
                downstream.dom_leg.deadline,
                TimelockSpec::BlockHeight { .. }
            )
        {
            return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
        }
        if upstream.counterparty_leg.chain_id == downstream.counterparty_leg.chain_id
            || upstream.counterparty_leg.chain_id == upstream.dom_leg.chain_id
            || downstream.counterparty_leg.chain_id == upstream.dom_leg.chain_id
        {
            // V1 already handles a shared clock. V2 intentionally covers the
            // three-chain case and keeps one unambiguous checkpoint per role.
            return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
        }

        let manifest = registry.manifest();
        if manifest.dom.runtime_identity.network == DomNetworkV1::Mainnet {
            return Err(RouteTimeAnchorErrorV2::MainnetDisabled);
        }
        if manifest.network_id == [0; 32]
            || registry.manifest_digest() == [0; 32]
            || manifest.epoch == 0
            || limits.valid_from_seconds < manifest.valid_from
            || limits.expires_at_seconds > manifest.expires_at
        {
            return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
        }
        let dom_profile_digest = dom_profile_digest(manifest)?;
        if upstream.dom_leg.chain_id != manifest.dom.chain_id
            || upstream.dom_leg.asset_id != manifest.dom.native_asset
            || upstream.dom_leg.adapter_profile_hash != dom_profile_digest
            || upstream.dom_leg.finality != manifest.dom.finality
            || downstream.dom_leg.finality != manifest.dom.finality
        {
            return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
        }

        let hub = CheckpointBindingV2 {
            role: CheckpointRoleV2::Hub,
            clock_kind: ClockKindV2::DomHeight,
            chain_id: manifest.dom.chain_id,
            genesis_hash: manifest.dom.genesis_hash,
            profile_digest: dom_profile_digest,
            timing: manifest.dom.timing,
            finality: manifest.dom.finality,
        };
        let upstream_counterparty = counterparty_binding(
            registry,
            &upstream.counterparty_leg,
            CheckpointRoleV2::UpstreamCounterparty,
        )?;
        let downstream_counterparty = counterparty_binding(
            registry,
            &downstream.counterparty_leg,
            CheckpointRoleV2::DownstreamCounterparty,
        )?;
        if upstream_counterparty.clock_kind == downstream_counterparty.clock_kind {
            // Different Bitcoin networks still do not share an anchor; this is
            // allowed. The check only rules out two EVM timestamp legs, which
            // V1 compares exactly without any conversion.
            if upstream_counterparty.clock_kind == ClockKindV2::EvmTimestamp {
                return Err(RouteTimeAnchorErrorV2::UnsupportedTopology);
            }
        }
        let upstream_terms_hash = upstream
            .terms_hash()
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
        let downstream_terms_hash = downstream
            .terms_hash()
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
        let route_scope_digest = route_scope_digest(upstream, downstream)?;
        let value = Self {
            network_id: manifest.network_id,
            registry_digest: registry.manifest_digest(),
            registry_epoch: manifest.epoch,
            upstream_terms_hash,
            downstream_terms_hash,
            route_scope_digest,
            limits,
            checkpoints: [hub, upstream_counterparty, downstream_counterparty],
        };
        value.validate_static()?;
        Ok(value)
    }

    pub(crate) fn validate_against(
        &self,
        registry: &ResolvedRegistryV1,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
    ) -> Result<()> {
        let expected = Self::from_registry(registry, upstream, downstream, self.limits)?;
        if expected != *self {
            return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_static(&self) -> Result<()> {
        if self.network_id == [0; 32]
            || self.registry_digest == [0; 32]
            || self.registry_epoch == 0
            || self.upstream_terms_hash == [0; 32]
            || self.downstream_terms_hash == [0; 32]
            || self.route_scope_digest == [0; 32]
            || self.limits.valid_from_seconds >= self.limits.expires_at_seconds
            || self.limits.max_evidence_age_seconds == 0
            || self.limits.max_anchor_interval_width_seconds == 0
            || self.limits.max_anchor_time_skew_seconds == 0
            || self.limits.max_upstream_funding_anchor_delay_seconds == 0
            || self.limits.max_downstream_funding_anchor_delay_seconds == 0
            || self.limits.hub_margin_seconds == 0
            || self.limits.counterparty_margin_seconds == 0
        {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        let lifetime = self
            .limits
            .expires_at_seconds
            .checked_sub(self.limits.valid_from_seconds)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        if self.limits.max_evidence_age_seconds > lifetime
            || self.limits.max_upstream_funding_anchor_delay_seconds > lifetime
            || self.limits.max_downstream_funding_anchor_delay_seconds > lifetime
            || self.checkpoints[0].role != CheckpointRoleV2::Hub
            || self.checkpoints[1].role != CheckpointRoleV2::UpstreamCounterparty
            || self.checkpoints[2].role != CheckpointRoleV2::DownstreamCounterparty
            || self.checkpoints[0].clock_kind != ClockKindV2::DomHeight
            || self.checkpoints[0].chain_id == self.checkpoints[1].chain_id
            || self.checkpoints[0].chain_id == self.checkpoints[2].chain_id
            || self.checkpoints[1].chain_id == self.checkpoints[2].chain_id
        {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        for checkpoint in &self.checkpoints {
            validate_checkpoint_binding(checkpoint)?;
        }
        let hub_floor =
            minimum_safety_margin_seconds(&self.checkpoints[0].timing, &self.checkpoints[0].timing)
                .map_err(|_| RouteTimeAnchorErrorV2::InvalidPolicy)?;
        let counterparty_floor =
            minimum_safety_margin_seconds(&self.checkpoints[1].timing, &self.checkpoints[2].timing)
                .map_err(|_| RouteTimeAnchorErrorV2::InvalidPolicy)?;
        let upstream_funding_floor = minimum_funding_anchor_delay(&self.checkpoints[1])?;
        let downstream_funding_floor = minimum_funding_anchor_delay(&self.checkpoints[2])?;
        if self.limits.hub_margin_seconds < hub_floor
            || self.limits.counterparty_margin_seconds < counterparty_floor
            || self.limits.max_upstream_funding_anchor_delay_seconds < upstream_funding_floor
            || self.limits.max_downstream_funding_anchor_delay_seconds < downstream_funding_floor
        {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        Ok(())
    }

    /// Exact DOM/upstream/downstream checkpoint identities frozen by policy.
    pub const fn checkpoint_bindings(&self) -> &[CheckpointBindingV2; 3] {
        &self.checkpoints
    }

    /// Registry network identity authenticated by both signatures and registry.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    /// Exact signed deployment-registry digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Exact monotonic deployment-registry epoch.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Canonical upstream settlement terms digest.
    pub const fn upstream_terms_hash(&self) -> Digest32 {
        self.upstream_terms_hash
    }

    /// Canonical downstream settlement terms digest.
    pub const fn downstream_terms_hash(&self) -> Digest32 {
        self.downstream_terms_hash
    }

    /// Domain-separated digest of both length-prefixed terms encodings.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.route_scope_digest
    }

    /// Signed freshness, uncertainty and margin limits.
    pub const fn limits(&self) -> RouteTimePolicyLimitsV2 {
        self.limits
    }

    /// Frozen canonical policy bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_static()?;
        encode_policy_v2(self)
    }

    /// Strictly decodes canonical policy bytes and refuses trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value = decode_policy_v2(bytes)?;
        value.validate_static()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// BLAKE2b-256 commitment signed by policy authorities.
    pub fn policy_digest(&self) -> Result<Digest32> {
        digest(ROUTE_TIME_POLICY_DOMAIN_V2, &self.canonical_bytes()?)
    }
}

/// One threshold-attested canonical checkpoint and its conservative time range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTimeCheckpointV2 {
    /// Fixed role copied from the signed policy.
    pub role: CheckpointRoleV2,
    /// Native clock copied from the signed policy.
    pub clock_kind: ClockKindV2,
    /// Exact registry chain identifier.
    pub chain_id: ChainId,
    /// Exact authenticated genesis hash.
    pub genesis_hash: Digest32,
    /// Exact authenticated timing/deployment profile digest.
    pub profile_digest: Digest32,
    /// Height of the route-specific frozen canonical anchor.
    pub anchor_height: u64,
    /// Hash of the frozen canonical anchor block.
    pub anchor_hash: Digest32,
    /// Parent hash, preventing a bare height/hash assertion.
    pub parent_hash: Digest32,
    /// Conservative lower wall-clock endpoint for the anchor's native time.
    pub time_lower_seconds: u64,
    /// Conservative upper wall-clock endpoint for the anchor's native time.
    pub time_upper_seconds: u64,
    /// Height of the canonical tip used to prove required confirmations.
    pub canonical_tip_height: u64,
    /// Hash of that canonical tip.
    pub canonical_tip_hash: Digest32,
    /// Commitment to the complete chain-specific canonicality/finality proof.
    pub canonicality_evidence_digest: Digest32,
}

/// Frozen canonical anchor identified by height, block hash and parent hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalAnchorObservationV2 {
    height: u64,
    block_hash: Digest32,
    parent_hash: Digest32,
}

impl CanonicalAnchorObservationV2 {
    /// Creates an exact canonical anchor observation.
    pub fn new(height: u64, block_hash: Digest32, parent_hash: Digest32) -> Self {
        Self {
            height,
            block_hash,
            parent_hash,
        }
    }
}

/// Conservative lower and upper wall-clock endpoints for a native-chain time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTimeRangeV2 {
    lower_seconds: u64,
    upper_seconds: u64,
}

impl CanonicalTimeRangeV2 {
    /// Creates a conservative inclusive time range.
    pub fn new(lower_seconds: u64, upper_seconds: u64) -> Self {
        Self {
            lower_seconds,
            upper_seconds,
        }
    }
}

/// Canonical tip and the proof commitment supporting its finality claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalTipObservationV2 {
    height: u64,
    block_hash: Digest32,
    canonicality_evidence_digest: Digest32,
}

impl CanonicalTipObservationV2 {
    /// Creates an exact canonical-tip observation and proof commitment.
    pub fn new(height: u64, block_hash: Digest32, canonicality_evidence_digest: Digest32) -> Self {
        Self {
            height,
            block_hash,
            canonicality_evidence_digest,
        }
    }
}

/// Chain-observed facts used to build one policy-bound canonical checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalCheckpointObservationV2 {
    anchor: CanonicalAnchorObservationV2,
    time_range: CanonicalTimeRangeV2,
    tip: CanonicalTipObservationV2,
}

impl CanonicalCheckpointObservationV2 {
    /// Groups the exact anchor, conservative time range and canonical tip.
    pub fn new(
        anchor: CanonicalAnchorObservationV2,
        time_range: CanonicalTimeRangeV2,
        tip: CanonicalTipObservationV2,
    ) -> Self {
        Self {
            anchor,
            time_range,
            tip,
        }
    }
}

impl CanonicalTimeCheckpointV2 {
    /// Constructs a checkpoint with identity fields copied from a policy
    /// binding. Chain-specific observers provide only canonical public facts.
    pub fn new(
        binding: CheckpointBindingV2,
        observation: CanonicalCheckpointObservationV2,
    ) -> Self {
        Self {
            role: binding.role,
            clock_kind: binding.clock_kind,
            chain_id: binding.chain_id,
            genesis_hash: binding.genesis_hash,
            profile_digest: binding.profile_digest,
            anchor_height: observation.anchor.height,
            anchor_hash: observation.anchor.block_hash,
            parent_hash: observation.anchor.parent_hash,
            time_lower_seconds: observation.time_range.lower_seconds,
            time_upper_seconds: observation.time_range.upper_seconds,
            canonical_tip_height: observation.tip.height,
            canonical_tip_hash: observation.tip.block_hash,
            canonicality_evidence_digest: observation.tip.canonicality_evidence_digest,
        }
    }
}

/// Fresh threshold-signed revalidation of all route checkpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteTimeEvidenceV2 {
    pub(crate) policy_digest: Digest32,
    pub(crate) route_scope_digest: Digest32,
    pub(crate) sequence: u64,
    pub(crate) observed_at_seconds: u64,
    pub(crate) expires_at_seconds: u64,
    pub(crate) checkpoints: [CanonicalTimeCheckpointV2; 3],
}

impl RouteTimeEvidenceV2 {
    /// Creates canonical evidence for the exact policy checkpoint order.
    pub fn new(
        policy: &RouteTimePolicyV2,
        sequence: u64,
        observed_at_seconds: u64,
        expires_at_seconds: u64,
        checkpoints: [CanonicalTimeCheckpointV2; 3],
    ) -> Result<Self> {
        let value = Self {
            policy_digest: policy.policy_digest()?,
            route_scope_digest: policy.route_scope_digest,
            sequence,
            observed_at_seconds,
            expires_at_seconds,
            checkpoints,
        };
        value.validate_at(policy, observed_at_seconds)?;
        Ok(value)
    }

    pub(crate) fn validate_at(&self, policy: &RouteTimePolicyV2, now: u64) -> Result<()> {
        policy.validate_static()?;
        if self.policy_digest != policy.policy_digest()?
            || self.route_scope_digest != policy.route_scope_digest
            || self.sequence == 0
            || self.observed_at_seconds < policy.limits.valid_from_seconds
            || self.expires_at_seconds > policy.limits.expires_at_seconds
            || self.observed_at_seconds >= self.expires_at_seconds
        {
            return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
        }
        let signed_lifetime = self
            .expires_at_seconds
            .checked_sub(self.observed_at_seconds)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        if signed_lifetime > policy.limits.max_evidence_age_seconds {
            return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
        }
        if now < policy.limits.valid_from_seconds || now >= policy.limits.expires_at_seconds {
            return Err(RouteTimeAnchorErrorV2::PolicyExpired);
        }
        if self.observed_at_seconds > now {
            return Err(RouteTimeAnchorErrorV2::EvidenceFromFuture);
        }
        if now >= self.expires_at_seconds
            || now
                .checked_sub(self.observed_at_seconds)
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?
                > policy.limits.max_evidence_age_seconds
        {
            return Err(RouteTimeAnchorErrorV2::EvidenceStale);
        }
        for (checkpoint, binding) in self.checkpoints.iter().zip(policy.checkpoints.iter()) {
            validate_checkpoint(checkpoint, binding, policy.limits, self.observed_at_seconds)?;
        }
        Ok(())
    }

    /// Policy digest covered by every evidence signature.
    pub const fn policy_digest(&self) -> Digest32 {
        self.policy_digest
    }

    /// Ordered settlement-terms scope covered by every evidence signature.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.route_scope_digest
    }

    /// Monotonic evidence/revalidation sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Trusted UNIX second attested by checkpoint authorities.
    pub const fn observed_at_seconds(&self) -> u64 {
        self.observed_at_seconds
    }

    /// First trusted UNIX second at which this evidence is stale.
    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }

    /// Exact hub/upstream/downstream checkpoint set.
    pub const fn checkpoints(&self) -> &[CanonicalTimeCheckpointV2; 3] {
        &self.checkpoints
    }

    /// Frozen canonical evidence bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        encode_evidence_v2(self)
    }

    /// Strictly decodes canonical evidence bytes and refuses trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value = decode_evidence_v2(bytes)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// BLAKE2b-256 commitment signed by checkpoint authorities.
    pub fn evidence_digest(&self) -> Result<Digest32> {
        digest(ROUTE_TIME_EVIDENCE_DOMAIN_V2, &self.canonical_bytes()?)
    }
}

/// Conservative absolute-time interval for one native deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlineIntervalV2 {
    /// Earliest second at which the native deadline may mature.
    pub earliest_seconds: u64,
    /// Latest second at which the native deadline may mature.
    pub latest_seconds: u64,
}

/// One proven worst-case ladder rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LadderIntervalProofV2 {
    /// Conservative interval for the upstream deadline.
    pub upstream: DeadlineIntervalV2,
    /// Conservative interval for the downstream deadline.
    pub downstream: DeadlineIntervalV2,
    /// Signed seconds margin added to `downstream.latest`.
    pub margin_seconds: u64,
}

/// Public admission checkpoint that a durable time store must retain in its
/// authenticated monotonic evidence ancestry before authorizing later work.
///
/// This pin intentionally excludes the old proof's process-opening epoch and
/// store revision: those capabilities become stale on restart. The immutable
/// route scope and policy plus the exact signed evidence logical key remain
/// sufficient to prove that a newer checkpoint descended through the store's
/// fail-closed anchor-continuity rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenRouteTimeCheckpointV2 {
    route_scope_digest: Digest32,
    policy_digest: Digest32,
    evidence_digest: Digest32,
    evidence_sequence: u64,
}

impl FrozenRouteTimeCheckpointV2 {
    /// Constructs a non-zero checkpoint frozen by authenticated admission.
    pub fn new(
        route_scope_digest: Digest32,
        policy_digest: Digest32,
        evidence_digest: Digest32,
        evidence_sequence: u64,
    ) -> Result<Self> {
        if route_scope_digest == [0; 32]
            || policy_digest == [0; 32]
            || evidence_digest == [0; 32]
            || evidence_sequence == 0
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        Ok(Self {
            route_scope_digest,
            policy_digest,
            evidence_digest,
            evidence_sequence,
        })
    }

    /// Exact ordered route-terms scope.
    pub const fn route_scope_digest(self) -> Digest32 {
        self.route_scope_digest
    }

    /// Exact threshold-authenticated static policy.
    pub const fn policy_digest(self) -> Digest32 {
        self.policy_digest
    }

    /// Exact threshold-authenticated evidence at admission.
    pub const fn evidence_digest(self) -> Digest32 {
        self.evidence_digest
    }

    /// Logical evidence sequence at admission.
    pub const fn evidence_sequence(self) -> u64 {
        self.evidence_sequence
    }
}

/// Complete public time-proof checkpoint retained by route admission.
///
/// The nested [`FrozenRouteTimeCheckpointV2`] is the only part used to prove
/// current evidence ancestry. The remaining fields identify the exact
/// historical ladder proof consumed by the original admission; they never
/// become a replacement for a current economic capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenRouteTimeProofCheckpointV2 {
    ancestry: FrozenRouteTimeCheckpointV2,
    proof_digest: Digest32,
    issued_at_seconds: u64,
    valid_until_seconds: u64,
    validated_at_seconds: u64,
}

impl FrozenRouteTimeProofCheckpointV2 {
    /// Constructs one internally coherent historical admission checkpoint.
    pub fn new(
        ancestry: FrozenRouteTimeCheckpointV2,
        proof_digest: Digest32,
        issued_at_seconds: u64,
        valid_until_seconds: u64,
        validated_at_seconds: u64,
    ) -> Result<Self> {
        if proof_digest == [0; 32]
            || issued_at_seconds == 0
            || issued_at_seconds > validated_at_seconds
            || validated_at_seconds >= valid_until_seconds
        {
            return Err(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch);
        }
        Ok(Self {
            ancestry,
            proof_digest,
            issued_at_seconds,
            valid_until_seconds,
            validated_at_seconds,
        })
    }

    /// Immutable scope/policy/evidence logical key used for current ancestry.
    pub const fn ancestry(self) -> FrozenRouteTimeCheckpointV2 {
        self.ancestry
    }

    /// Exact historical worst-case ladder proof digest.
    pub const fn proof_digest(self) -> Digest32 {
        self.proof_digest
    }

    /// Trusted second at which the original proof was issued.
    pub const fn issued_at_seconds(self) -> u64 {
        self.issued_at_seconds
    }

    /// Exclusive historical proof-validity boundary.
    pub const fn valid_until_seconds(self) -> u64 {
        self.valid_until_seconds
    }

    /// Trusted second at which admission consumed the original proof.
    pub const fn validated_at_seconds(self) -> u64 {
        self.validated_at_seconds
    }
}

/// Opaque, single-use proof issued by the durable authority.
///
/// This type intentionally does not implement `Clone`, `Copy` or a public
/// constructor. `route-composer` consumes it when creating V2 bindings.
pub struct VerifiedRouteTimeLadderV2 {
    pub(crate) upstream_terms_hash: Digest32,
    pub(crate) downstream_terms_hash: Digest32,
    pub(crate) route_scope_digest: Digest32,
    pub(crate) policy_digest: Digest32,
    pub(crate) evidence_digest: Digest32,
    pub(crate) hub: LadderIntervalProofV2,
    pub(crate) counterparty: LadderIntervalProofV2,
    pub(crate) binding_digest: Digest32,
    pub(crate) evidence_sequence: u64,
    pub(crate) issued_at_seconds: u64,
    pub(crate) valid_until_seconds: u64,
    pub(crate) store_revision: u64,
    pub(crate) store_opening_epoch: u64,
}

/// Move-only authentication of the exact historical ladder consumed by a
/// durable route admission.
///
/// This proof has no public constructor or codec and is deliberately not a
/// current economic capability. It can only be consumed by the route composer
/// to reconstruct the original admission binding.
pub struct VerifiedFrozenRouteTimeLadderV2 {
    proof: VerifiedRouteTimeLadderV2,
    validated_at_seconds: u64,
}

impl core::fmt::Debug for VerifiedFrozenRouteTimeLadderV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedFrozenRouteTimeLadderV2")
            .field("route_scope_digest", &self.proof.route_scope_digest)
            .field("policy_digest", &self.proof.policy_digest)
            .field("evidence_digest", &self.proof.evidence_digest)
            .field("evidence_sequence", &self.proof.evidence_sequence)
            .field("issued_at_seconds", &self.proof.issued_at_seconds)
            .field("valid_until_seconds", &self.proof.valid_until_seconds)
            .field("validated_at_seconds", &self.validated_at_seconds)
            .finish()
    }
}

impl VerifiedFrozenRouteTimeLadderV2 {
    pub(crate) const fn new(proof: VerifiedRouteTimeLadderV2, validated_at_seconds: u64) -> Self {
        Self {
            proof,
            validated_at_seconds,
        }
    }

    /// Upstream terms digest authenticated by the historical proof.
    pub const fn upstream_terms_hash(&self) -> Digest32 {
        self.proof.upstream_terms_hash
    }

    /// Downstream terms digest authenticated by the historical proof.
    pub const fn downstream_terms_hash(&self) -> Digest32 {
        self.proof.downstream_terms_hash
    }

    /// Exact ordered route scope.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.proof.route_scope_digest
    }

    /// Exact historical policy digest.
    pub const fn policy_digest(&self) -> Digest32 {
        self.proof.policy_digest
    }

    /// Exact historical evidence digest.
    pub const fn evidence_digest(&self) -> Digest32 {
        self.proof.evidence_digest
    }

    /// Exact historical ladder-proof digest.
    pub const fn binding_digest(&self) -> Digest32 {
        self.proof.binding_digest
    }

    /// Historical evidence sequence.
    pub const fn evidence_sequence(&self) -> u64 {
        self.proof.evidence_sequence
    }

    /// Original proof issuance second.
    pub const fn issued_at_seconds(&self) -> u64 {
        self.proof.issued_at_seconds
    }

    /// Original proof exclusive validity boundary.
    pub const fn valid_until_seconds(&self) -> u64 {
        self.proof.valid_until_seconds
    }

    /// Original durable admission validation second.
    pub const fn validated_at_seconds(&self) -> u64 {
        self.validated_at_seconds
    }

    /// Recomputed conservative DOM-height rung.
    pub const fn hub_proof(&self) -> LadderIntervalProofV2 {
        self.proof.hub
    }

    /// Recomputed conservative counterparty rung.
    pub const fn counterparty_proof(&self) -> LadderIntervalProofV2 {
        self.proof.counterparty
    }
}

impl core::fmt::Debug for VerifiedRouteTimeLadderV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedRouteTimeLadderV2")
            .field("route_scope_digest", &self.route_scope_digest)
            .field("policy_digest", &self.policy_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("hub", &self.hub)
            .field("counterparty", &self.counterparty)
            .field("evidence_sequence", &self.evidence_sequence)
            .field("issued_at_seconds", &self.issued_at_seconds)
            .field("valid_until_seconds", &self.valid_until_seconds)
            .finish_non_exhaustive()
    }
}

impl VerifiedRouteTimeLadderV2 {
    /// Upstream terms digest proven by this capability.
    pub const fn upstream_terms_hash(&self) -> Digest32 {
        self.upstream_terms_hash
    }

    /// Downstream terms digest proven by this capability.
    pub const fn downstream_terms_hash(&self) -> Digest32 {
        self.downstream_terms_hash
    }

    /// Exact route scope committed by policy and evidence.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.route_scope_digest
    }

    /// Threshold-authenticated policy digest.
    pub const fn policy_digest(&self) -> Digest32 {
        self.policy_digest
    }

    /// Fresh threshold-authenticated evidence digest.
    pub const fn evidence_digest(&self) -> Digest32 {
        self.evidence_digest
    }

    /// Proven DOM-height ladder in conservative seconds.
    pub const fn hub_proof(&self) -> LadderIntervalProofV2 {
        self.hub
    }

    /// Proven mixed counterparty ladder in conservative seconds.
    pub const fn counterparty_proof(&self) -> LadderIntervalProofV2 {
        self.counterparty
    }

    /// Commitment to policy, evidence, intervals, margins and exact terms.
    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }

    /// Monotonic evidence sequence used for this proof.
    pub const fn evidence_sequence(&self) -> u64 {
        self.evidence_sequence
    }

    /// Trusted second at which the durable authority issued this proof.
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// First trusted second at which evidence or a relative funding horizon
    /// makes this proof unusable.
    pub const fn valid_until_seconds(&self) -> u64 {
        self.valid_until_seconds
    }

    pub(crate) const fn store_revision(&self) -> u64 {
        self.store_revision
    }

    pub(crate) const fn store_opening_epoch(&self) -> u64 {
        self.store_opening_epoch
    }
}

/// Move-only ladder capability revalidated against the live durable store.
///
/// Its lifetime holds an exclusive borrow of the route-time authority until a
/// consumer such as `route-composer` destroys it. Combined with the store's
/// process lock, evidence cannot be refreshed, invalidated or reopened between
/// final revalidation and composition.
pub struct CurrentRouteTimeLadderV2<'authority> {
    proof: VerifiedRouteTimeLadderV2,
    validated_at_seconds: u64,
    _exclusive_authority: core::marker::PhantomData<&'authority mut ()>,
}

impl core::fmt::Debug for CurrentRouteTimeLadderV2<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CurrentRouteTimeLadderV2")
            .field("proof", &self.proof)
            .field("validated_at_seconds", &self.validated_at_seconds)
            .finish()
    }
}

impl<'authority> CurrentRouteTimeLadderV2<'authority> {
    pub(crate) const fn new(proof: VerifiedRouteTimeLadderV2, validated_at_seconds: u64) -> Self {
        Self {
            proof,
            validated_at_seconds,
            _exclusive_authority: core::marker::PhantomData,
        }
    }

    /// Upstream terms digest proven by this current capability.
    pub const fn upstream_terms_hash(&self) -> Digest32 {
        self.proof.upstream_terms_hash()
    }

    /// Downstream terms digest proven by this current capability.
    pub const fn downstream_terms_hash(&self) -> Digest32 {
        self.proof.downstream_terms_hash()
    }

    /// Exact ordered route scope committed by policy and evidence.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.proof.route_scope_digest()
    }

    /// Threshold-authenticated complete policy digest.
    pub const fn policy_digest(&self) -> Digest32 {
        self.proof.policy_digest()
    }

    /// Fresh threshold-authenticated evidence digest.
    pub const fn evidence_digest(&self) -> Digest32 {
        self.proof.evidence_digest()
    }

    /// Conservative DOM-height ladder.
    pub const fn hub_proof(&self) -> LadderIntervalProofV2 {
        self.proof.hub_proof()
    }

    /// Conservative mixed counterparty ladder.
    pub const fn counterparty_proof(&self) -> LadderIntervalProofV2 {
        self.proof.counterparty_proof()
    }

    /// Digest of the exact issued time-ladder proof.
    pub const fn binding_digest(&self) -> Digest32 {
        self.proof.binding_digest()
    }

    /// Monotonic evidence sequence.
    pub const fn evidence_sequence(&self) -> u64 {
        self.proof.evidence_sequence()
    }

    /// Trusted issuance second.
    pub const fn issued_at_seconds(&self) -> u64 {
        self.proof.issued_at_seconds()
    }

    /// First second at which this proof is no longer usable.
    pub const fn valid_until_seconds(&self) -> u64 {
        self.proof.valid_until_seconds()
    }

    /// Trusted second of the final durable-store revalidation.
    pub const fn validated_at_seconds(&self) -> u64 {
        self.validated_at_seconds
    }
}

pub(crate) fn prove_ladder(
    policy: &RouteTimePolicyV2,
    evidence: &RouteTimeEvidenceV2,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
    now: u64,
    store_revision: u64,
    store_opening_epoch: u64,
) -> Result<VerifiedRouteTimeLadderV2> {
    evidence.validate_at(policy, now)?;
    let upstream_hash = upstream
        .terms_hash()
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
    let downstream_hash = downstream
        .terms_hash()
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
    let scope = route_scope_digest(upstream, downstream)?;
    if upstream_hash != policy.upstream_terms_hash
        || downstream_hash != policy.downstream_terms_hash
        || scope != policy.route_scope_digest
    {
        return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
    }

    let hub_up = project_deadline(
        upstream.dom_leg.deadline,
        &policy.checkpoints[0],
        &evidence.checkpoints[0],
        0,
    )?;
    let hub_down = project_deadline(
        downstream.dom_leg.deadline,
        &policy.checkpoints[0],
        &evidence.checkpoints[0],
        0,
    )?;
    let counterparty_up = project_deadline(
        upstream.counterparty_leg.deadline,
        &policy.checkpoints[1],
        &evidence.checkpoints[1],
        policy.limits.max_upstream_funding_anchor_delay_seconds,
    )?;
    let counterparty_down = project_deadline(
        downstream.counterparty_leg.deadline,
        &policy.checkpoints[2],
        &evidence.checkpoints[2],
        policy.limits.max_downstream_funding_anchor_delay_seconds,
    )?;
    for interval in [hub_up, hub_down, counterparty_up, counterparty_down] {
        if interval.earliest_seconds > interval.latest_seconds {
            return Err(RouteTimeAnchorErrorV2::ImpossibleInterval);
        }
        // If the earliest possible maturity is not strictly in the future,
        // the route may already be refundable and cannot be newly composed.
        if now >= interval.earliest_seconds {
            return Err(RouteTimeAnchorErrorV2::DeadlinePassed);
        }
    }
    let hub = prove_rung(hub_up, hub_down, policy.limits.hub_margin_seconds)?;
    let counterparty = prove_rung(
        counterparty_up,
        counterparty_down,
        policy.limits.counterparty_margin_seconds,
    )?;
    let policy_digest = policy.policy_digest()?;
    let evidence_digest = evidence.evidence_digest()?;
    let valid_until_seconds = proof_valid_until(policy, evidence, upstream, downstream)?
        .min(hub_up.earliest_seconds)
        .min(hub_down.earliest_seconds)
        .min(counterparty_up.earliest_seconds)
        .min(counterparty_down.earliest_seconds);
    if now >= valid_until_seconds {
        return Err(RouteTimeAnchorErrorV2::AnchorStale);
    }
    let mut bytes = Vec::with_capacity(32 * 5 + 8 * 11);
    bytes.extend_from_slice(&upstream_hash);
    bytes.extend_from_slice(&downstream_hash);
    bytes.extend_from_slice(&scope);
    bytes.extend_from_slice(&policy_digest);
    bytes.extend_from_slice(&evidence_digest);
    for proof in [hub, counterparty] {
        bytes.extend_from_slice(&proof.upstream.earliest_seconds.to_be_bytes());
        bytes.extend_from_slice(&proof.upstream.latest_seconds.to_be_bytes());
        bytes.extend_from_slice(&proof.downstream.earliest_seconds.to_be_bytes());
        bytes.extend_from_slice(&proof.downstream.latest_seconds.to_be_bytes());
        bytes.extend_from_slice(&proof.margin_seconds.to_be_bytes());
    }
    bytes.extend_from_slice(&evidence.sequence.to_be_bytes());
    bytes.extend_from_slice(&now.to_be_bytes());
    bytes.extend_from_slice(&valid_until_seconds.to_be_bytes());
    let binding_digest = digest(ROUTE_TIME_LADDER_DOMAIN_V2, &bytes)?;
    Ok(VerifiedRouteTimeLadderV2 {
        upstream_terms_hash: upstream_hash,
        downstream_terms_hash: downstream_hash,
        route_scope_digest: scope,
        policy_digest,
        evidence_digest,
        hub,
        counterparty,
        binding_digest,
        evidence_sequence: evidence.sequence,
        issued_at_seconds: now,
        valid_until_seconds,
        store_revision,
        store_opening_epoch,
    })
}

fn prove_rung(
    upstream: DeadlineIntervalV2,
    downstream: DeadlineIntervalV2,
    margin_seconds: u64,
) -> Result<LadderIntervalProofV2> {
    let protected_downstream = downstream
        .latest_seconds
        .checked_add(margin_seconds)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    if upstream.earliest_seconds < protected_downstream {
        return Err(RouteTimeAnchorErrorV2::UnsafeWindow);
    }
    Ok(LadderIntervalProofV2 {
        upstream,
        downstream,
        margin_seconds,
    })
}

fn project_deadline(
    deadline: TimelockSpec,
    binding: &CheckpointBindingV2,
    checkpoint: &CanonicalTimeCheckpointV2,
    max_funding_anchor_delay_seconds: u64,
) -> Result<DeadlineIntervalV2> {
    match (binding.clock_kind, deadline) {
        (ClockKindV2::EvmTimestamp, TimelockSpec::TimestampSeconds { value }) => {
            if value == 0 {
                return Err(RouteTimeAnchorErrorV2::DeadlinePassed);
            }
            Ok(DeadlineIntervalV2 {
                earliest_seconds: value,
                latest_seconds: value,
            })
        }
        (ClockKindV2::Solana, TimelockSpec::TimestampSeconds { value }) => {
            if value == 0 {
                return Err(RouteTimeAnchorErrorV2::DeadlinePassed);
            }
            Ok(DeadlineIntervalV2 {
                earliest_seconds: value.saturating_sub(SOLANA_CLOCK_DRIFT_SECONDS_V2),
                latest_seconds: value
                    .checked_add(SOLANA_CLOCK_DRIFT_SECONDS_V2)
                    .ok_or(RouteTimeAnchorErrorV2::Overflow)?,
            })
        }
        (
            ClockKindV2::DomHeight | ClockKindV2::Bitcoin | ClockKindV2::Monero,
            TimelockSpec::BlockHeight { value },
        ) => {
            let delta = value
                .checked_sub(checkpoint.anchor_height)
                .ok_or(RouteTimeAnchorErrorV2::DeadlinePassed)?;
            let earliest_offset = delta
                .checked_mul(u64::from(binding.timing.min_block_seconds))
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
            let latest_offset = delta
                .checked_mul(u64::from(binding.timing.max_block_seconds))
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
            Ok(DeadlineIntervalV2 {
                earliest_seconds: checkpoint
                    .time_lower_seconds
                    .checked_add(earliest_offset)
                    .ok_or(RouteTimeAnchorErrorV2::Overflow)?,
                latest_seconds: checkpoint
                    .time_upper_seconds
                    .checked_add(latest_offset)
                    .ok_or(RouteTimeAnchorErrorV2::Overflow)?,
            })
        }
        (ClockKindV2::Bitcoin, TimelockSpec::BtcTime512s { value }) => {
            if value == 0 || value > u64::from(u16::MAX) || max_funding_anchor_delay_seconds == 0 {
                return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
            }
            let nominal = value
                .checked_mul(512)
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
            let median_uncertainty = BTC_MTP_SAMPLE_INTERVALS_V2
                .checked_mul(u64::from(binding.timing.max_block_seconds))
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
            let earliest_offset = nominal.saturating_sub(median_uncertainty);
            let latest_offset = nominal
                .checked_add(511)
                .and_then(|value| value.checked_add(median_uncertainty))
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
            Ok(DeadlineIntervalV2 {
                earliest_seconds: checkpoint
                    .time_lower_seconds
                    .checked_add(earliest_offset)
                    .ok_or(RouteTimeAnchorErrorV2::Overflow)?,
                latest_seconds: checkpoint
                    .time_upper_seconds
                    .checked_add(max_funding_anchor_delay_seconds)
                    .and_then(|value| value.checked_add(latest_offset))
                    .ok_or(RouteTimeAnchorErrorV2::Overflow)?,
            })
        }
        _ => Err(RouteTimeAnchorErrorV2::UnsupportedTopology),
    }
}

fn proof_valid_until(
    policy: &RouteTimePolicyV2,
    evidence: &RouteTimeEvidenceV2,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<u64> {
    let mut valid_until = evidence
        .expires_at_seconds
        .min(policy.limits.expires_at_seconds);
    for (deadline, checkpoint, horizon) in [
        (
            upstream.counterparty_leg.deadline,
            evidence.checkpoints[1],
            policy.limits.max_upstream_funding_anchor_delay_seconds,
        ),
        (
            downstream.counterparty_leg.deadline,
            evidence.checkpoints[2],
            policy.limits.max_downstream_funding_anchor_delay_seconds,
        ),
    ] {
        if matches!(deadline, TimelockSpec::BtcTime512s { .. }) {
            let horizon_end = checkpoint
                .time_upper_seconds
                .checked_add(horizon)
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
            valid_until = valid_until.min(horizon_end);
        }
    }
    Ok(valid_until)
}

fn validate_checkpoint(
    checkpoint: &CanonicalTimeCheckpointV2,
    binding: &CheckpointBindingV2,
    limits: RouteTimePolicyLimitsV2,
    observed_at: u64,
) -> Result<()> {
    if checkpoint.role != binding.role
        || checkpoint.clock_kind != binding.clock_kind
        || checkpoint.chain_id != binding.chain_id
        || checkpoint.genesis_hash != binding.genesis_hash
        || checkpoint.profile_digest != binding.profile_digest
    {
        return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
    }
    if checkpoint.anchor_hash == [0; 32]
        || checkpoint.parent_hash == [0; 32]
        || checkpoint.canonical_tip_hash == [0; 32]
        || checkpoint.canonicality_evidence_digest == [0; 32]
        || checkpoint.time_lower_seconds == 0
        || checkpoint.time_lower_seconds > checkpoint.time_upper_seconds
    {
        return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
    }
    let width = checkpoint
        .time_upper_seconds
        .checked_sub(checkpoint.time_lower_seconds)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    if width > limits.max_anchor_interval_width_seconds {
        return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
    }
    let maximum_future = observed_at
        .checked_add(limits.max_future_skew_seconds)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    let latest_acceptable_past = checkpoint
        .time_upper_seconds
        .checked_add(limits.max_anchor_time_skew_seconds)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    if checkpoint.time_lower_seconds > maximum_future || observed_at > latest_acceptable_past {
        return Err(RouteTimeAnchorErrorV2::AnchorStale);
    }
    let confirmations_minus_one = u64::from(
        binding
            .finality
            .min_confirmations
            .checked_sub(1)
            .ok_or(RouteTimeAnchorErrorV2::InvalidPolicy)?,
    );
    let required_tip = checkpoint
        .anchor_height
        .checked_add(confirmations_minus_one)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    if checkpoint.canonical_tip_height < required_tip
        || (checkpoint.canonical_tip_height == checkpoint.anchor_height
            && checkpoint.canonical_tip_hash != checkpoint.anchor_hash)
    {
        return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
    }
    Ok(())
}

fn validate_checkpoint_binding(binding: &CheckpointBindingV2) -> Result<()> {
    if binding.chain_id.0 == [0; 32]
        || binding.genesis_hash == [0; 32]
        || binding.profile_digest == [0; 32]
        || binding.timing.min_block_seconds == 0
        || binding.timing.max_block_seconds == 0
        || binding.timing.min_block_seconds > binding.timing.max_block_seconds
        || binding.timing.max_reorg_seconds == 0
        || binding.timing.observation_seconds == 0
        || binding.timing.broadcast_seconds == 0
        || binding.finality.min_confirmations == 0
        || binding.finality.max_reorg_depth < binding.finality.min_confirmations
    {
        return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
    }
    minimum_safety_margin_seconds(&binding.timing, &binding.timing)
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidPolicy)?;
    Ok(())
}

fn minimum_funding_anchor_delay(binding: &CheckpointBindingV2) -> Result<u64> {
    u64::from(binding.timing.max_block_seconds)
        .checked_mul(u64::from(binding.finality.min_confirmations))
        .and_then(|value| value.checked_add(u64::from(binding.timing.observation_seconds)))
        .and_then(|value| value.checked_add(u64::from(binding.timing.broadcast_seconds)))
        .ok_or(RouteTimeAnchorErrorV2::Overflow)
}

fn counterparty_binding(
    registry: &ResolvedRegistryV1,
    leg: &kaystra_core::types::LegTermsV1,
    role: CheckpointRoleV2,
) -> Result<CheckpointBindingV2> {
    let resolved = registry
        .resolve_chain(leg.chain_id)
        .ok_or(RouteTimeAnchorErrorV2::RegistryMismatch)?;
    let profile = resolved.profile();
    let profile_digest = profile
        .profile_digest()
        .map_err(|_| RouteTimeAnchorErrorV2::RegistryMismatch)?;
    if leg.adapter_profile_hash != profile_digest || leg.finality != profile.finality {
        return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
    }
    let (clock_kind, genesis_hash) = match (profile.kind, resolved.deployment(), leg.deadline) {
        (
            ChainKindV1::Evm { evm_chain_id, .. },
            ChainDeploymentV1::Evm(deployment),
            TimelockSpec::TimestampSeconds { .. },
        ) if leg.mechanism == LockMechanism::ConditionLock && evm_chain_id != 1 => {
            (ClockKindV2::EvmTimestamp, deployment.genesis_hash)
        }
        (
            ChainKindV1::Bitcoin { .. },
            ChainDeploymentV1::Bitcoin(deployment),
            TimelockSpec::BlockHeight { .. } | TimelockSpec::BtcTime512s { .. },
        ) if leg.mechanism == LockMechanism::SchnorrAdaptor => {
            (ClockKindV2::Bitcoin, deployment.genesis_hash)
        }
        (
            ChainKindV1::Monero { .. },
            ChainDeploymentV1::Monero(deployment),
            TimelockSpec::BlockHeight { .. },
        ) if leg.mechanism == LockMechanism::CrossCurveSharedSpend => {
            (ClockKindV2::Monero, deployment.genesis_hash)
        }
        (
            ChainKindV1::Solana { .. },
            ChainDeploymentV1::Solana(deployment),
            TimelockSpec::TimestampSeconds { .. },
        ) if leg.mechanism == LockMechanism::CrossCurveConditionLock => {
            (ClockKindV2::Solana, deployment.genesis_hash)
        }
        (
            ChainKindV1::Evm {
                evm_chain_id: 1, ..
            },
            _,
            _,
        ) => return Err(RouteTimeAnchorErrorV2::MainnetDisabled),
        _ => return Err(RouteTimeAnchorErrorV2::UnsupportedTopology),
    };
    Ok(CheckpointBindingV2 {
        role,
        clock_kind,
        chain_id: profile.chain_id,
        genesis_hash,
        profile_digest,
        timing: profile.timing,
        finality: profile.finality,
    })
}

fn dom_profile_digest(manifest: &RegistryManifestV1) -> Result<Digest32> {
    let deployment = manifest.dom;
    let fields: [&[u8]; 12] = [
        &deployment.chain_id.0,
        &deployment.genesis_hash,
        &deployment.consensus_rules_digest,
        &deployment.scriptless_api_version.to_be_bytes(),
        &deployment.timing.min_block_seconds.to_be_bytes(),
        &deployment.timing.max_block_seconds.to_be_bytes(),
        &deployment.timing.max_reorg_seconds.to_be_bytes(),
        &deployment.timing.observation_seconds.to_be_bytes(),
        &deployment.timing.broadcast_seconds.to_be_bytes(),
        &deployment.finality.min_confirmations.to_be_bytes(),
        &deployment.finality.max_reorg_depth.to_be_bytes(),
        &deployment.native_asset.0,
    ];
    let mut hash = Blake2bVar::new(32).map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
    hash.update(DOM_PROFILE_DOMAIN_V1);
    for field in fields {
        let length =
            u64::try_from(field.len()).map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
        hash.update(&length.to_be_bytes());
        hash.update(field);
    }
    let mut output = [0u8; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
    Ok(output)
}

/// Recomputes the DOM adapter-profile digest already frozen into settlement
/// terms, but only from a registry value whose threshold signatures were
/// verified. This is the same V1 domain used by productive route admission.
pub fn resolved_dom_profile_digest_v1(registry: &ResolvedRegistryV1) -> Result<Digest32> {
    dom_profile_digest(registry.manifest())
}

/// Derives the exact length-delimited route scope used by policy and evidence.
pub fn route_scope_digest(
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<Digest32> {
    let upstream_bytes = upstream
        .canonical_bytes()
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
    let downstream_bytes = downstream
        .canonical_bytes()
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidTerms)?;
    let mut bytes = Vec::with_capacity(upstream_bytes.len() + downstream_bytes.len() + 16);
    bytes.extend_from_slice(
        &u64::try_from(upstream_bytes.len())
            .map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&upstream_bytes);
    bytes.extend_from_slice(
        &u64::try_from(downstream_bytes.len())
            .map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&downstream_bytes);
    digest(ROUTE_TIME_SCOPE_DOMAIN_V2, &bytes)
}

pub(crate) fn digest(domain: &[u8], bytes: &[u8]) -> Result<Digest32> {
    let mut hash = Blake2bVar::new(32).map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
    hash.update(domain);
    hash.update(bytes);
    let mut output = [0u8; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
    Ok(output)
}

pub(crate) fn authority_set_digest_parts(threshold: u16, keys: &[[u8; 32]]) -> Result<Digest32> {
    let mut bytes = Vec::with_capacity(4 + keys.len() * 32);
    bytes.extend_from_slice(&threshold.to_be_bytes());
    bytes.extend_from_slice(
        &u16::try_from(keys.len())
            .map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?
            .to_be_bytes(),
    );
    for key in keys {
        bytes.extend_from_slice(key);
    }
    digest(crate::ROUTE_TIME_AUTHORITY_SET_DOMAIN_V2, &bytes)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn binding(kind: ClockKindV2, min: u32, max: u32) -> CheckpointBindingV2 {
        CheckpointBindingV2 {
            role: CheckpointRoleV2::Hub,
            clock_kind: kind,
            chain_id: ChainId([1; 32]),
            genesis_hash: [2; 32],
            profile_digest: [3; 32],
            timing: ChainTimingBoundsV1 {
                min_block_seconds: min,
                max_block_seconds: max,
                max_reorg_seconds: 10_000,
                observation_seconds: 1,
                broadcast_seconds: 1,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 1,
            },
        }
    }

    fn checkpoint(anchor_height: u64, lower: u64, upper: u64) -> CanonicalTimeCheckpointV2 {
        CanonicalTimeCheckpointV2::new(
            binding(ClockKindV2::DomHeight, 1, 2),
            CanonicalCheckpointObservationV2::new(
                CanonicalAnchorObservationV2::new(anchor_height, [4; 32], [5; 32]),
                CanonicalTimeRangeV2::new(lower, upper),
                CanonicalTipObservationV2::new(anchor_height, [4; 32], [6; 32]),
            ),
        )
    }

    #[test]
    fn a_monero_height_deadline_projects_like_the_other_height_clocks() {
        // Regression: the Monero clock was bindable but had no projection
        // arm, so a route with an XMR leg failed closed at proof time.
        let binding = binding(ClockKindV2::Monero, 100, 140);
        let checkpoint = checkpoint(1_000, 5_000, 5_050);
        assert_eq!(
            project_deadline(
                TimelockSpec::BlockHeight { value: 1_010 },
                &binding,
                &checkpoint,
                0,
            ),
            Ok(DeadlineIntervalV2 {
                earliest_seconds: 5_000 + 10 * 100,
                latest_seconds: 5_050 + 10 * 140,
            }),
        );
    }

    #[test]
    fn a_solana_timestamp_projects_with_the_drift_band_on_both_sides() {
        let binding = binding(ClockKindV2::Solana, 1, 1);
        let checkpoint = checkpoint(1, 1, 1);
        assert_eq!(
            project_deadline(
                TimelockSpec::TimestampSeconds {
                    value: 2_000_000_000,
                },
                &binding,
                &checkpoint,
                0,
            ),
            Ok(DeadlineIntervalV2 {
                earliest_seconds: 2_000_000_000 - SOLANA_CLOCK_DRIFT_SECONDS_V2,
                latest_seconds: 2_000_000_000 + SOLANA_CLOCK_DRIFT_SECONDS_V2,
            }),
        );
        // Zero refuses, and a Solana clock holds no height deadline.
        assert!(project_deadline(
            TimelockSpec::TimestampSeconds { value: 0 },
            &binding,
            &checkpoint,
            0,
        )
        .is_err());
        assert!(project_deadline(
            TimelockSpec::BlockHeight { value: 5 },
            &binding,
            &checkpoint,
            0,
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn worst_case_rung_is_equivalent_to_checked_inequality(
            upstream_earliest in 0u64..10_000_000,
            upstream_width in 0u64..10_000,
            downstream_earliest in 0u64..10_000_000,
            downstream_width in 0u64..10_000,
            margin in 1u64..100_000,
        ) {
            let upstream = DeadlineIntervalV2 {
                earliest_seconds: upstream_earliest,
                latest_seconds: upstream_earliest + upstream_width,
            };
            let downstream = DeadlineIntervalV2 {
                earliest_seconds: downstream_earliest,
                latest_seconds: downstream_earliest + downstream_width,
            };
            let expected = downstream.latest_seconds
                .checked_add(margin)
                .map(|minimum| upstream.earliest_seconds >= minimum)
                .unwrap_or(false);
            prop_assert_eq!(prove_rung(upstream, downstream, margin).is_ok(), expected);
        }

        #[test]
        fn height_projection_uses_min_for_earliest_and_max_for_latest(
            anchor_height in 1u64..1_000_000,
            delta in 0u64..1_000_000,
            anchor_lower in 1u64..1_000_000_000,
            anchor_width in 0u64..1_000,
            min_seconds in 1u32..100,
            spread in 0u32..500,
        ) {
            let max_seconds = min_seconds + spread;
            let binding = binding(ClockKindV2::DomHeight, min_seconds, max_seconds);
            let checkpoint = checkpoint(
                anchor_height,
                anchor_lower,
                anchor_lower + anchor_width,
            );
            prop_assert_eq!(
                project_deadline(
                    TimelockSpec::BlockHeight { value: anchor_height + delta },
                    &binding,
                    &checkpoint,
                    0,
                ),
                Ok(DeadlineIntervalV2 {
                    earliest_seconds: anchor_lower + delta * u64::from(min_seconds),
                    latest_seconds: anchor_lower
                        + anchor_width
                        + delta * u64::from(max_seconds),
                }),
            );
        }

        #[test]
        fn evm_to_bitcoin_rung_uses_the_complete_relative_time_upper_bound(
            evm_deadline in 1u64..2_000_000_000,
            anchor_lower in 1u64..1_000_000_000,
            anchor_width in 0u64..1_000,
            relative_units in 1u64..65_536,
            maximum_block_seconds in 1u32..1_000,
            funding_horizon in 1u64..100_000,
            margin in 1u64..100_000,
        ) {
            let evm_binding = binding(ClockKindV2::EvmTimestamp, 1, 1);
            let bitcoin_binding =
                binding(ClockKindV2::Bitcoin, 1, maximum_block_seconds);
            let bitcoin_checkpoint = CanonicalTimeCheckpointV2::new(
                bitcoin_binding,
                CanonicalCheckpointObservationV2::new(
                    CanonicalAnchorObservationV2::new(700, [4; 32], [5; 32]),
                    CanonicalTimeRangeV2::new(anchor_lower, anchor_lower + anchor_width),
                    CanonicalTipObservationV2::new(700, [4; 32], [6; 32]),
                ),
            );
            let evm = project_deadline(
                TimelockSpec::TimestampSeconds { value: evm_deadline },
                &evm_binding,
                &bitcoin_checkpoint,
                0,
            );
            prop_assert!(evm.is_ok());
            let evm = evm.unwrap_or(DeadlineIntervalV2 {
                earliest_seconds: 0,
                latest_seconds: 0,
            });
            let bitcoin = project_deadline(
                TimelockSpec::BtcTime512s { value: relative_units },
                &bitcoin_binding,
                &bitcoin_checkpoint,
                funding_horizon,
            );
            prop_assert!(bitcoin.is_ok());
            let bitcoin = bitcoin.unwrap_or(DeadlineIntervalV2 {
                earliest_seconds: 0,
                latest_seconds: 0,
            });
            let nominal = relative_units * 512;
            let mtp_uncertainty =
                BTC_MTP_SAMPLE_INTERVALS_V2 * u64::from(maximum_block_seconds);
            prop_assert_eq!(evm.earliest_seconds, evm_deadline);
            prop_assert_eq!(evm.latest_seconds, evm_deadline);
            prop_assert_eq!(
                bitcoin.latest_seconds,
                anchor_lower
                    + anchor_width
                    + funding_horizon
                    + nominal
                    + 511
                    + mtp_uncertainty,
            );
            let expected = bitcoin
                .latest_seconds
                .checked_add(margin)
                .is_some_and(|minimum| evm_deadline >= minimum);
            prop_assert_eq!(prove_rung(evm, bitcoin, margin).is_ok(), expected);
        }
    }

    #[test]
    fn projection_overflow_is_never_saturated_into_a_valid_interval() {
        let binding = binding(ClockKindV2::DomHeight, u32::MAX, u32::MAX);
        let checkpoint = checkpoint(1, u64::MAX - 1, u64::MAX - 1);
        assert_eq!(
            project_deadline(
                TimelockSpec::BlockHeight { value: 2 },
                &binding,
                &checkpoint,
                0,
            ),
            Err(RouteTimeAnchorErrorV2::Overflow)
        );
    }

    #[test]
    fn btc_relative_time_includes_the_complete_signed_funding_horizon() {
        let binding = binding(ClockKindV2::Bitcoin, 500, 700);
        let checkpoint = checkpoint(700, 1_000_000, 1_000_010);
        assert_eq!(
            project_deadline(
                TimelockSpec::BtcTime512s { value: 20 },
                &binding,
                &checkpoint,
                3_600,
            ),
            Ok(DeadlineIntervalV2 {
                earliest_seconds: 1_003_240,
                latest_seconds: 1_021_361,
            })
        );
        assert_eq!(
            project_deadline(
                TimelockSpec::BtcTime512s { value: 20 },
                &binding,
                &checkpoint,
                0,
            ),
            Err(RouteTimeAnchorErrorV2::InvalidPolicy)
        );
    }
}
