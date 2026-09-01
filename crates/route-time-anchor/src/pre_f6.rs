//! RFQ-scoped time authority that exists before F6 Acceptance.
//!
//! The composed-route ladder is necessarily post-terms and therefore cannot
//! authorize quote expiry without a temporal cycle.  This module keeps a
//! separate, versioned authority for the negotiation clock only.  Its initial
//! production profile is deliberately narrow: the authenticated DOM finalized
//! height.  Bitcoin BIP68 and heterogeneous refund clocks remain settlement
//! facts and are never converted into this clock.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use deployment_registry::{AuthoritySetV1, DomNetworkV1, ResolvedRegistryV1};
use kaystra_core::types::{Digest32, FinalityPolicyV1};
use rfq::v2::{NativeClockKindV2, NegotiationClockV2, NegotiationObservationV2};
use std::path::Path;
use store::{ProductionStoreBindingV1, Store, StoreError};

use crate::{resolved_dom_profile_digest_v1, Result, RouteTimeAnchorErrorV2};

const ZERO_DIGEST: Digest32 = [0; 32];
const POLICY_MAGIC_V2: &[u8; 8] = b"DOMPF6P2";
const EVIDENCE_MAGIC_V2: &[u8; 8] = b"DOMPF6E2";
const SIGNED_MAGIC_V2: &[u8; 8] = b"DOMPF6S2";
const SCOPE_DOMAIN_V2: &[u8] = b"DOM-INTEROP/PRE-F6-TIME/SCOPE/V2\0";
const POLICY_DOMAIN_V2: &[u8] = b"DOM-INTEROP/PRE-F6-TIME/POLICY/V2\0";
const EVIDENCE_DOMAIN_V2: &[u8] = b"DOM-INTEROP/PRE-F6-TIME/EVIDENCE/V2\0";
const AUTHORITY_SET_DOMAIN_V2: &[u8] = b"DOM-INTEROP/PRE-F6-TIME/AUTHORITY-SET/V2\0";
const STORE_BINDING_DOMAIN_V2: &[u8] = b"DOM-INTEROP/PRE-F6-TIME/STORE/V2\0";
const FORMAT_VERSION_V2: u16 = 2;
const JOURNAL_KIND_V2: u16 = 1;
const TRUSTED_CLOCK_ENTITY_V2: &[u8] = b"DOM-INTEROP/PRE-F6-TIME/TRUSTED-CLOCK/V2";
const MAX_AUTHORITIES_V2: usize = 16;
const MAX_HISTORY_ROWS_V2: usize = 4_096;
const MAX_EVIDENCE_LIFETIME_SECONDS_V2: u64 = 300;
const POLICY_BYTES_V2: usize = 403;
const EVIDENCE_BYTES_V2: usize = 379;
const SIGNATURE_BYTES_V2: usize = 66;
const MAX_SIGNED_BYTES_V2: usize =
    8 + 2 + 4 + EVIDENCE_BYTES_V2 + 2 + MAX_AUTHORITIES_V2 * SIGNATURE_BYTES_V2;

/// Caller-supplied immutable identifiers used to build one pre-F6 time scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6TimeScopeRequestV2 {
    /// Authenticated deployment network.
    pub network_id: Digest32,
    /// Relay/F6 session.
    pub session_id: Digest32,
    /// Route executor identity.
    pub route_id: Digest32,
    /// Two-settlement composition identity.
    pub composition_id: Digest32,
    /// Content-derived F6 V2 RFQ identity.
    pub rfq_id: Digest32,
    /// Exact chain/profile/authority clock selected by the RFQ.
    pub negotiation_clock: NegotiationClockV2,
    /// Authenticated registry digest.
    pub registry_digest: Digest32,
    /// Monotonic registry epoch.
    pub registry_epoch: u64,
    /// Complete authenticated production profile bundle.
    pub profile_bundle_digest: Digest32,
}

/// Immutable RFQ-scoped identity covered by policy, evidence and storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6TimeScopeV2 {
    request: PreF6TimeScopeRequestV2,
    scope_digest: Digest32,
}

impl PreF6TimeScopeV2 {
    /// Validates every nonzero pin and freezes the canonical scope digest.
    pub fn new(request: PreF6TimeScopeRequestV2) -> Result<Self> {
        request
            .negotiation_clock
            .validate()
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidPolicy)?;
        if [
            request.network_id,
            request.session_id,
            request.route_id,
            request.composition_id,
            request.rfq_id,
            request.registry_digest,
            request.profile_bundle_digest,
        ]
        .contains(&ZERO_DIGEST)
            || request.registry_epoch == 0
        {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        let bytes = encode_scope_request(request);
        let scope_digest = digest_parts(SCOPE_DOMAIN_V2, &[&bytes])?;
        Ok(Self {
            request,
            scope_digest,
        })
    }

    /// Authenticated network.
    pub const fn network_id(self) -> Digest32 {
        self.request.network_id
    }

    /// Exact session.
    pub const fn session_id(self) -> Digest32 {
        self.request.session_id
    }

    /// Exact route.
    pub const fn route_id(self) -> Digest32 {
        self.request.route_id
    }

    /// Exact composition.
    pub const fn composition_id(self) -> Digest32 {
        self.request.composition_id
    }

    /// Exact RFQ.
    pub const fn rfq_id(self) -> Digest32 {
        self.request.rfq_id
    }

    /// Exact negotiation clock.
    pub const fn negotiation_clock(self) -> NegotiationClockV2 {
        self.request.negotiation_clock
    }

    /// Authenticated registry digest.
    pub const fn registry_digest(self) -> Digest32 {
        self.request.registry_digest
    }

    /// Authenticated registry epoch.
    pub const fn registry_epoch(self) -> u64 {
        self.request.registry_epoch
    }

    /// Complete profile-bundle commitment.
    pub const fn profile_bundle_digest(self) -> Digest32 {
        self.request.profile_bundle_digest
    }

    /// Canonical scope digest.
    pub const fn scope_digest(self) -> Digest32 {
        self.scope_digest
    }
}

/// Signed freshness bounds for pre-F6 evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6TimePolicyLimitsV2 {
    /// First trusted UNIX second at which the policy is valid.
    pub valid_from_seconds: u64,
    /// Exclusive policy expiration.
    pub expires_at_seconds: u64,
    /// Maximum lifetime and accepted age of one evidence statement.
    pub max_evidence_age_seconds: u64,
}

/// Deterministic registry-bound pre-F6 time policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6TimePolicyV2 {
    scope: PreF6TimeScopeV2,
    genesis_hash: Digest32,
    finality: FinalityPolicyV1,
    limits: PreF6TimePolicyLimitsV2,
}

impl PreF6TimePolicyV2 {
    /// Builds the narrow initial producer: authenticated DOM finalized height.
    pub fn from_registry(
        scope: PreF6TimeScopeV2,
        registry: &ResolvedRegistryV1,
        limits: PreF6TimePolicyLimitsV2,
    ) -> Result<Self> {
        let manifest = registry.manifest();
        let clock = scope.negotiation_clock();
        if manifest.dom.runtime_identity.network == DomNetworkV1::Mainnet {
            return Err(RouteTimeAnchorErrorV2::MainnetDisabled);
        }
        if scope.network_id() != manifest.network_id
            || scope.registry_digest() != registry.manifest_digest()
            || scope.registry_epoch() != manifest.epoch
            || clock.chain_id != manifest.dom.chain_id
            || clock.profile_digest != resolved_dom_profile_digest_v1(registry)?
            || clock.kind != NativeClockKindV2::BlockHeight
            || limits.valid_from_seconds < manifest.valid_from
            || limits.expires_at_seconds > manifest.expires_at
        {
            return Err(RouteTimeAnchorErrorV2::RegistryMismatch);
        }
        let value = Self {
            scope,
            genesis_hash: manifest.dom.genesis_hash,
            finality: manifest.dom.finality,
            limits,
        };
        value.validate_static()?;
        Ok(value)
    }

    fn validate_static(self) -> Result<()> {
        let clock = self.scope.negotiation_clock();
        if self.genesis_hash == ZERO_DIGEST
            || clock.kind != NativeClockKindV2::BlockHeight
            || self.finality.min_confirmations == 0
            || self.finality.max_reorg_depth < self.finality.min_confirmations
            || self.limits.valid_from_seconds >= self.limits.expires_at_seconds
            || self.limits.max_evidence_age_seconds == 0
            || self.limits.max_evidence_age_seconds > MAX_EVIDENCE_LIFETIME_SECONDS_V2
        {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        let lifetime = self
            .limits
            .expires_at_seconds
            .checked_sub(self.limits.valid_from_seconds)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        if self.limits.max_evidence_age_seconds > lifetime {
            return Err(RouteTimeAnchorErrorV2::InvalidPolicy);
        }
        Ok(())
    }

    /// Exact RFQ scope.
    pub const fn scope(self) -> PreF6TimeScopeV2 {
        self.scope
    }

    /// DOM genesis bound by the authenticated registry.
    pub const fn genesis_hash(self) -> Digest32 {
        self.genesis_hash
    }

    /// Finality policy used to admit a finalized height.
    pub const fn finality(self) -> FinalityPolicyV1 {
        self.finality
    }

    /// Signed freshness bounds.
    pub const fn limits(self) -> PreF6TimePolicyLimitsV2 {
        self.limits
    }

    /// Strict canonical policy bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>> {
        self.validate_static()?;
        let mut out = Vec::with_capacity(POLICY_BYTES_V2);
        out.extend_from_slice(POLICY_MAGIC_V2);
        out.extend_from_slice(&FORMAT_VERSION_V2.to_be_bytes());
        out.extend_from_slice(&encode_scope_request(self.scope.request));
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.finality.min_confirmations.to_be_bytes());
        out.extend_from_slice(&self.finality.max_reorg_depth.to_be_bytes());
        out.extend_from_slice(&self.limits.valid_from_seconds.to_be_bytes());
        out.extend_from_slice(&self.limits.expires_at_seconds.to_be_bytes());
        out.extend_from_slice(&self.limits.max_evidence_age_seconds.to_be_bytes());
        if out.len() != POLICY_BYTES_V2 {
            return Err(RouteTimeAnchorErrorV2::DigestFailure);
        }
        Ok(out)
    }

    /// Threshold evidence binds this deterministic policy digest.
    pub fn policy_digest(self) -> Result<Digest32> {
        digest_parts(POLICY_DOMAIN_V2, &[&self.canonical_bytes()?])
    }
}

/// Public finalized DOM checkpoint supplied by chain observers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6CanonicalCheckpointV2 {
    /// Exact negotiation chain.
    pub chain_id: kaystra_core::types::ChainId,
    /// Exact authenticated profile.
    pub profile_digest: Digest32,
    /// Exact authenticated genesis.
    pub genesis_hash: Digest32,
    /// Native clock represented by the checkpoint.
    pub clock_kind: NativeClockKindV2,
    /// Conservative finalized height exposed to F6 as `now`.
    pub finalized_height: u64,
    /// Hash at the finalized height.
    pub finalized_hash: Digest32,
    /// Parent hash of the finalized block.
    pub finalized_parent_hash: Digest32,
    /// Consensus timestamp of the finalized block.
    pub finalized_timestamp_seconds: u64,
    /// Observed canonical tip height proving the finality depth.
    pub canonical_tip_height: u64,
    /// Hash of the observed canonical tip.
    pub canonical_tip_hash: Digest32,
    /// Commitment to the complete canonicality/ancestry proof.
    pub canonicality_evidence_digest: Digest32,
}

impl PreF6CanonicalCheckpointV2 {
    fn validate(self, policy: PreF6TimePolicyV2, observed_at_seconds: u64) -> Result<()> {
        let clock = policy.scope.negotiation_clock();
        let finality_depth = u64::from(policy.finality.max_reorg_depth)
            .max(u64::from(policy.finality.min_confirmations));
        let required_tip = self
            .finalized_height
            .checked_add(finality_depth)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        if self.chain_id != clock.chain_id
            || self.profile_digest != clock.profile_digest
            || self.genesis_hash != policy.genesis_hash
            || self.clock_kind != clock.kind
            || self.finalized_height == 0
            || self.finalized_hash == ZERO_DIGEST
            || self.finalized_parent_hash == ZERO_DIGEST
            || self.finalized_timestamp_seconds == 0
            || self.finalized_timestamp_seconds > observed_at_seconds
            || self.canonical_tip_height < required_tip
            || self.canonical_tip_hash == ZERO_DIGEST
            || self.canonicality_evidence_digest == ZERO_DIGEST
        {
            return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
        }
        Ok(())
    }
}

/// One policy-scoped monotonic finalized-height observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6TimeEvidenceV2 {
    policy_digest: Digest32,
    scope_digest: Digest32,
    sequence: u64,
    previous_evidence_digest: Digest32,
    observed_at_seconds: u64,
    expires_at_seconds: u64,
    checkpoint: PreF6CanonicalCheckpointV2,
}

impl PreF6TimeEvidenceV2 {
    /// Constructs evidence linked to the previous durable evidence digest.
    pub fn new(
        policy: PreF6TimePolicyV2,
        sequence: u64,
        previous_evidence_digest: Digest32,
        observed_at_seconds: u64,
        expires_at_seconds: u64,
        checkpoint: PreF6CanonicalCheckpointV2,
    ) -> Result<Self> {
        let value = Self {
            policy_digest: policy.policy_digest()?,
            scope_digest: policy.scope.scope_digest(),
            sequence,
            previous_evidence_digest,
            observed_at_seconds,
            expires_at_seconds,
            checkpoint,
        };
        value.validate_shape(policy)?;
        Ok(value)
    }

    fn validate_shape(self, policy: PreF6TimePolicyV2) -> Result<()> {
        policy.validate_static()?;
        if self.policy_digest != policy.policy_digest()?
            || self.scope_digest != policy.scope.scope_digest()
            || self.sequence == 0
            || (self.sequence == 1 && self.previous_evidence_digest != ZERO_DIGEST)
            || (self.sequence > 1 && self.previous_evidence_digest == ZERO_DIGEST)
            || self.observed_at_seconds < policy.limits.valid_from_seconds
            || self.expires_at_seconds > policy.limits.expires_at_seconds
            || self.observed_at_seconds >= self.expires_at_seconds
        {
            return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
        }
        let lifetime = self
            .expires_at_seconds
            .checked_sub(self.observed_at_seconds)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        if lifetime > policy.limits.max_evidence_age_seconds {
            return Err(RouteTimeAnchorErrorV2::InvalidEvidence);
        }
        self.checkpoint.validate(policy, self.observed_at_seconds)
    }

    fn validate_current(self, policy: PreF6TimePolicyV2, trusted_now_seconds: u64) -> Result<()> {
        self.validate_shape(policy)?;
        if trusted_now_seconds < policy.limits.valid_from_seconds
            || trusted_now_seconds >= policy.limits.expires_at_seconds
        {
            return Err(RouteTimeAnchorErrorV2::PolicyExpired);
        }
        if self.observed_at_seconds > trusted_now_seconds {
            return Err(RouteTimeAnchorErrorV2::EvidenceFromFuture);
        }
        if trusted_now_seconds >= self.expires_at_seconds
            || trusted_now_seconds
                .checked_sub(self.observed_at_seconds)
                .ok_or(RouteTimeAnchorErrorV2::Overflow)?
                > policy.limits.max_evidence_age_seconds
        {
            return Err(RouteTimeAnchorErrorV2::EvidenceStale);
        }
        Ok(())
    }

    /// Monotonic evidence sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Previous evidence commitment, or zero only for sequence one.
    pub const fn previous_evidence_digest(self) -> Digest32 {
        self.previous_evidence_digest
    }

    /// Trusted observation second.
    pub const fn observed_at_seconds(self) -> u64 {
        self.observed_at_seconds
    }

    /// Exclusive freshness boundary.
    pub const fn expires_at_seconds(self) -> u64 {
        self.expires_at_seconds
    }

    /// Exact finalized checkpoint.
    pub const fn checkpoint(self) -> PreF6CanonicalCheckpointV2 {
        self.checkpoint
    }

    /// Canonical evidence bytes.
    pub fn canonical_bytes(self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(EVIDENCE_BYTES_V2);
        out.extend_from_slice(EVIDENCE_MAGIC_V2);
        out.extend_from_slice(&FORMAT_VERSION_V2.to_be_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.scope_digest);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.previous_evidence_digest);
        out.extend_from_slice(&self.observed_at_seconds.to_be_bytes());
        out.extend_from_slice(&self.expires_at_seconds.to_be_bytes());
        put_checkpoint(&mut out, self.checkpoint);
        if out.len() != EVIDENCE_BYTES_V2 {
            return Err(RouteTimeAnchorErrorV2::DigestFailure);
        }
        Ok(out)
    }

    /// Strict decoder revalidated against the exact deterministic policy.
    pub fn decode(bytes: &[u8], policy: PreF6TimePolicyV2) -> Result<Self> {
        if bytes.len() != EVIDENCE_BYTES_V2 || bytes.get(..8) != Some(EVIDENCE_MAGIC_V2.as_slice())
        {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        let mut cursor = 8usize;
        if take_u16(bytes, &mut cursor)? != FORMAT_VERSION_V2 {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        let value = Self {
            policy_digest: take_32(bytes, &mut cursor)?,
            scope_digest: take_32(bytes, &mut cursor)?,
            sequence: take_u64(bytes, &mut cursor)?,
            previous_evidence_digest: take_32(bytes, &mut cursor)?,
            observed_at_seconds: take_u64(bytes, &mut cursor)?,
            expires_at_seconds: take_u64(bytes, &mut cursor)?,
            checkpoint: take_checkpoint(bytes, &mut cursor)?,
        };
        value.validate_shape(policy)?;
        if cursor != bytes.len() || value.canonical_bytes()?.as_slice() != bytes {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Digest covered by every evidence signature.
    pub fn evidence_digest(self) -> Result<Digest32> {
        digest_parts(EVIDENCE_DOMAIN_V2, &[&self.canonical_bytes()?])
    }
}

/// One indexed BIP340 signature over pre-F6 evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreF6TimeSignatureV2 {
    /// Index in the externally pinned evidence authority set.
    pub signer_index: u16,
    /// Canonical BIP340 signature.
    pub signature: [u8; 64],
}

/// Canonical pre-F6 evidence plus ordered threshold signatures.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedPreF6TimeEvidenceV2 {
    evidence_bytes: Vec<u8>,
    signatures: Vec<PreF6TimeSignatureV2>,
}

impl core::fmt::Debug for SignedPreF6TimeEvidenceV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedPreF6TimeEvidenceV2")
            .field("evidence_bytes", &self.evidence_bytes.len())
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

impl SignedPreF6TimeEvidenceV2 {
    /// Wraps canonical evidence and a strictly ordered signature set.
    pub fn new(
        evidence: PreF6TimeEvidenceV2,
        signatures: Vec<PreF6TimeSignatureV2>,
    ) -> Result<Self> {
        validate_signature_shape(&signatures)?;
        Ok(Self {
            evidence_bytes: evidence.canonical_bytes()?,
            signatures,
        })
    }

    /// Strict storage/transport bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        validate_signature_shape(&self.signatures)?;
        let evidence_len = u32::try_from(self.evidence_bytes.len())
            .map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
        let signature_count = u16::try_from(self.signatures.len())
            .map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
        let mut out = Vec::with_capacity(
            8 + 2 + 4 + self.evidence_bytes.len() + 2 + self.signatures.len() * SIGNATURE_BYTES_V2,
        );
        out.extend_from_slice(SIGNED_MAGIC_V2);
        out.extend_from_slice(&FORMAT_VERSION_V2.to_be_bytes());
        out.extend_from_slice(&evidence_len.to_be_bytes());
        out.extend_from_slice(&self.evidence_bytes);
        out.extend_from_slice(&signature_count.to_be_bytes());
        for signature in &self.signatures {
            out.extend_from_slice(&signature.signer_index.to_be_bytes());
            out.extend_from_slice(&signature.signature);
        }
        if out.len() > MAX_SIGNED_BYTES_V2 {
            return Err(RouteTimeAnchorErrorV2::BoundExceeded);
        }
        Ok(out)
    }

    /// Strict decoder bound to one exact policy.
    pub fn decode(bytes: &[u8], policy: PreF6TimePolicyV2) -> Result<Self> {
        if bytes.len() > MAX_SIGNED_BYTES_V2
            || bytes.len() < 8 + 2 + 4 + EVIDENCE_BYTES_V2 + 2 + SIGNATURE_BYTES_V2
            || bytes.get(..8) != Some(SIGNED_MAGIC_V2.as_slice())
        {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        let mut cursor = 8usize;
        if take_u16(bytes, &mut cursor)? != FORMAT_VERSION_V2 {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        if usize::try_from(take_u32(bytes, &mut cursor)?)
            .map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?
            != EVIDENCE_BYTES_V2
        {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        let evidence_bytes = take_slice(bytes, &mut cursor, EVIDENCE_BYTES_V2)?.to_vec();
        PreF6TimeEvidenceV2::decode(&evidence_bytes, policy)?;
        let count = usize::from(take_u16(bytes, &mut cursor)?);
        if count == 0 || count > MAX_AUTHORITIES_V2 {
            return Err(RouteTimeAnchorErrorV2::BoundExceeded);
        }
        let remaining = count
            .checked_mul(SIGNATURE_BYTES_V2)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        if bytes.len().checked_sub(cursor) != Some(remaining) {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(PreF6TimeSignatureV2 {
                signer_index: take_u16(bytes, &mut cursor)?,
                signature: take_64(bytes, &mut cursor)?,
            });
        }
        let value = Self {
            evidence_bytes,
            signatures,
        };
        validate_signature_shape(&value.signatures)?;
        if cursor != bytes.len() || value.canonical_bytes()?.as_slice() != bytes {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

/// Result of installing fresh pre-F6 evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreF6TimeInstallOutcomeV2 {
    /// A strictly linked next observation was appended.
    Installed,
    /// Exact signed head replay; no new row was appended.
    AlreadyCurrent,
}

/// Move-only current negotiation-time capability.
pub struct CurrentPreF6NegotiationTimeV2 {
    scope_digest: Digest32,
    negotiation_clock: NegotiationClockV2,
    observed_value: u64,
    evidence_digest: Digest32,
    evidence_sequence: u64,
    issued_at_seconds: u64,
    valid_until_seconds: u64,
    store_revision: u64,
}

impl core::fmt::Debug for CurrentPreF6NegotiationTimeV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CurrentPreF6NegotiationTimeV2")
            .field("evidence_sequence", &self.evidence_sequence)
            .field("valid_until_seconds", &self.valid_until_seconds)
            .finish_non_exhaustive()
    }
}

impl CurrentPreF6NegotiationTimeV2 {
    /// Exact RFQ-scoped time authority.
    pub const fn scope_digest(&self) -> Digest32 {
        self.scope_digest
    }

    /// Exact F6 V2 negotiation clock.
    pub const fn negotiation_clock(&self) -> NegotiationClockV2 {
        self.negotiation_clock
    }

    /// Current native value, never converted.
    pub const fn observed_value(&self) -> u64 {
        self.observed_value
    }

    /// Threshold-authenticated evidence digest.
    pub const fn evidence_digest(&self) -> Digest32 {
        self.evidence_digest
    }

    /// Monotonic evidence sequence.
    pub const fn evidence_sequence(&self) -> u64 {
        self.evidence_sequence
    }

    /// Trusted issuance second.
    pub const fn issued_at_seconds(&self) -> u64 {
        self.issued_at_seconds
    }

    /// Exclusive freshness boundary.
    pub const fn valid_until_seconds(&self) -> u64 {
        self.valid_until_seconds
    }

    /// Durable journal revision.
    pub const fn store_revision(&self) -> u64 {
        self.store_revision
    }

    /// Public F6 core value extracted from this authority.
    pub const fn observation(&self) -> NegotiationObservationV2 {
        NegotiationObservationV2 {
            clock: self.negotiation_clock,
            value: self.observed_value,
        }
    }
}

/// Strict owner-only monotonic evidence store.
pub struct DurablePreF6TimeStoreV2 {
    store: Store,
    policy: PreF6TimePolicyV2,
    authorities: AuthoritySetV1,
}

impl core::fmt::Debug for DurablePreF6TimeStoreV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurablePreF6TimeStoreV2")
            .field("scope_digest", &self.policy.scope.scope_digest)
            .finish_non_exhaustive()
    }
}

impl DurablePreF6TimeStoreV2 {
    /// Exact immutable RFQ scope authenticated by this physical authority.
    ///
    /// Composition roots use this before opening any dependent store, so a
    /// transplanted time authority is refused without leaving a partial F6
    /// creation prefix behind.
    pub const fn scope_digest(&self) -> Digest32 {
        self.policy.scope.scope_digest
    }

    /// Exact native negotiation clock authenticated by this authority.
    pub const fn negotiation_clock(&self) -> NegotiationClockV2 {
        self.policy.scope.negotiation_clock()
    }

    /// Creates a new strict production authority.
    pub fn create_production(
        path: &Path,
        policy: PreF6TimePolicyV2,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        let binding = production_binding(policy, &authorities, secp)?;
        let value = Self {
            store: Store::create_production(path, binding)
                .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?,
            policy,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Opens an existing strict production authority.
    pub fn open_production(
        path: &Path,
        policy: PreF6TimePolicyV2,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        let binding = production_binding(policy, &authorities, secp)?;
        let value = Self {
            store: Store::open_production(path, binding)
                .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?,
            policy,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Resumes only a pristine create prefix authorized by provisioning.
    pub fn resume_create_production(
        path: &Path,
        policy: PreF6TimePolicyV2,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        let binding = production_binding(policy, &authorities, secp)?;
        let value = Self {
            store: Store::resume_create_production(path, binding)
                .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?,
            policy,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Opens an initialized RFQ-scoped time authority or completes an
    /// externally provisioned lazy-binding prefix after the authenticated RFQ
    /// fixes the final policy scope.
    pub fn open_or_resume_prepared_production(
        path: &Path,
        preparation_digest: Digest32,
        policy: PreF6TimePolicyV2,
        authorities: AuthoritySetV1,
        secp: &SecpContext,
    ) -> Result<Self> {
        let preparation = ProductionStoreBindingV1::new(preparation_digest)
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        let binding = production_binding(policy, &authorities, secp)?;
        let value = Self {
            store: Store::open_or_resume_prepared_production(path, preparation, binding)
                .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?,
            policy,
            authorities,
        };
        value.audit(secp)?;
        Ok(value)
    }

    /// Installs or exactly replays fresh evidence and returns a current
    /// move-only capability from the durable head.
    pub fn install_and_prove_current_pre_f6_time(
        &mut self,
        signed: &SignedPreF6TimeEvidenceV2,
        secp: &SecpContext,
        trusted_now_seconds: u64,
    ) -> Result<(PreF6TimeInstallOutcomeV2, CurrentPreF6NegotiationTimeV2)> {
        self.advance_trusted_clock(trusted_now_seconds)?;
        let history = self.audit(secp)?;
        let (evidence, signed_bytes) = verify_signed(signed, self.policy, &self.authorities, secp)?;
        evidence.validate_current(self.policy, trusted_now_seconds)?;
        let outcome = match history.last() {
            Some(head) if head.signed_bytes == signed_bytes => {
                PreF6TimeInstallOutcomeV2::AlreadyCurrent
            }
            Some(head) => {
                validate_next(head, evidence)?;
                if history.len() >= MAX_HISTORY_ROWS_V2 {
                    return Err(RouteTimeAnchorErrorV2::BoundExceeded);
                }
                self.store
                    .append_journal(JOURNAL_KIND_V2, &signed_bytes)
                    .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
                PreF6TimeInstallOutcomeV2::Installed
            }
            None => {
                if evidence.sequence != 1 || evidence.previous_evidence_digest != ZERO_DIGEST {
                    return Err(RouteTimeAnchorErrorV2::EvidenceRollback);
                }
                self.store
                    .append_journal(JOURNAL_KIND_V2, &signed_bytes)
                    .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
                PreF6TimeInstallOutcomeV2::Installed
            }
        };
        let installed = self.audit(secp)?;
        let head = installed
            .last()
            .ok_or(RouteTimeAnchorErrorV2::CorruptState)?;
        if head.signed_bytes != signed_bytes || head.evidence != evidence {
            return Err(RouteTimeAnchorErrorV2::CorruptState);
        }
        let revision =
            u64::try_from(installed.len()).map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
        let capability = CurrentPreF6NegotiationTimeV2 {
            scope_digest: self.policy.scope.scope_digest,
            negotiation_clock: self.policy.scope.negotiation_clock(),
            observed_value: evidence.checkpoint.finalized_height,
            evidence_digest: evidence.evidence_digest()?,
            evidence_sequence: evidence.sequence,
            issued_at_seconds: trusted_now_seconds,
            valid_until_seconds: evidence.expires_at_seconds,
            store_revision: revision,
        };
        Ok((outcome, capability))
    }

    /// Re-audits the complete signed head and proves that it remains current
    /// at a non-rollback trusted wall observation. Production F6 calls this
    /// for every reserve, selection and acceptance; it must never cache an
    /// earlier capability through its expiry.
    pub fn prove_current_pre_f6_time(
        &mut self,
        secp: &SecpContext,
        trusted_now_seconds: u64,
    ) -> Result<CurrentPreF6NegotiationTimeV2> {
        self.advance_trusted_clock(trusted_now_seconds)?;
        let history = self.audit(secp)?;
        let head = history
            .last()
            .ok_or(RouteTimeAnchorErrorV2::InvalidEvidence)?;
        head.evidence
            .validate_current(self.policy, trusted_now_seconds)?;
        let revision =
            u64::try_from(history.len()).map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
        Ok(CurrentPreF6NegotiationTimeV2 {
            scope_digest: self.policy.scope.scope_digest,
            negotiation_clock: self.policy.scope.negotiation_clock(),
            observed_value: head.evidence.checkpoint.finalized_height,
            evidence_digest: head.evidence.evidence_digest()?,
            evidence_sequence: head.evidence.sequence,
            issued_at_seconds: trusted_now_seconds,
            valid_until_seconds: head.evidence.expires_at_seconds,
            store_revision: revision,
        })
    }

    fn advance_trusted_clock(&mut self, trusted_now_seconds: u64) -> Result<()> {
        match self
            .store
            .record_monotonic_high_water(TRUSTED_CLOCK_ENTITY_V2, trusted_now_seconds)
        {
            Ok(_) => Ok(()),
            Err(StoreError::RevisionConflict) => Err(RouteTimeAnchorErrorV2::ClockRollback),
            Err(_) => Err(RouteTimeAnchorErrorV2::StorageUnavailable),
        }
    }

    fn audit(&self, secp: &SecpContext) -> Result<Vec<RetainedEvidenceV2>> {
        production_binding(self.policy, &self.authorities, secp)?;
        let rows = self
            .store
            .read_journal()
            .map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)?;
        if rows.len() > MAX_HISTORY_ROWS_V2 {
            return Err(RouteTimeAnchorErrorV2::BoundExceeded);
        }
        let mut retained = Vec::with_capacity(rows.len());
        for row in rows {
            if row.kind != JOURNAL_KIND_V2 || row.payload.len() > MAX_SIGNED_BYTES_V2 {
                return Err(RouteTimeAnchorErrorV2::CorruptState);
            }
            let signed = SignedPreF6TimeEvidenceV2::decode(&row.payload, self.policy)?;
            let (evidence, signed_bytes) =
                verify_signed(&signed, self.policy, &self.authorities, secp)?;
            if let Some(previous) = retained.last() {
                validate_next(previous, evidence)
                    .map_err(|_| RouteTimeAnchorErrorV2::CorruptState)?;
            } else if evidence.sequence != 1 || evidence.previous_evidence_digest != ZERO_DIGEST {
                return Err(RouteTimeAnchorErrorV2::CorruptState);
            }
            retained.push(RetainedEvidenceV2 {
                evidence,
                signed_bytes,
            });
        }
        Ok(retained)
    }
}

struct RetainedEvidenceV2 {
    evidence: PreF6TimeEvidenceV2,
    signed_bytes: Vec<u8>,
}

fn validate_next(previous: &RetainedEvidenceV2, next: PreF6TimeEvidenceV2) -> Result<()> {
    let expected_sequence = previous
        .evidence
        .sequence
        .checked_add(1)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    if next.sequence != expected_sequence
        || next.previous_evidence_digest != previous.evidence.evidence_digest()?
        || next.observed_at_seconds < previous.evidence.observed_at_seconds
        || next.checkpoint.finalized_height < previous.evidence.checkpoint.finalized_height
    {
        return Err(RouteTimeAnchorErrorV2::EvidenceRollback);
    }
    if next.checkpoint.finalized_height == previous.evidence.checkpoint.finalized_height
        && (next.checkpoint.finalized_hash != previous.evidence.checkpoint.finalized_hash
            || next.checkpoint.finalized_parent_hash
                != previous.evidence.checkpoint.finalized_parent_hash)
    {
        return Err(RouteTimeAnchorErrorV2::AnchorReorged);
    }
    Ok(())
}

fn production_binding(
    policy: PreF6TimePolicyV2,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<ProductionStoreBindingV1> {
    policy.validate_static()?;
    let digest = digest_parts(
        STORE_BINDING_DOMAIN_V2,
        &[
            &policy.policy_digest()?,
            &authority_set_digest(authorities, secp)?,
        ],
    )?;
    ProductionStoreBindingV1::new(digest).map_err(|_| RouteTimeAnchorErrorV2::StorageUnavailable)
}

fn verify_signed(
    signed: &SignedPreF6TimeEvidenceV2,
    policy: PreF6TimePolicyV2,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(PreF6TimeEvidenceV2, Vec<u8>)> {
    validate_authorities(authorities, secp)?;
    validate_signature_shape(&signed.signatures)?;
    let evidence = PreF6TimeEvidenceV2::decode(&signed.evidence_bytes, policy)?;
    let digest = evidence.evidence_digest()?;
    for signature in &signed.signatures {
        let key = authorities
            .xonly_keys()
            .get(usize::from(signature.signer_index))
            .ok_or(RouteTimeAnchorErrorV2::InvalidSignature)?;
        secp.verify_bip340(key, &digest, &signature.signature)
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidSignature)?;
    }
    if signed.signatures.len() < usize::from(authorities.threshold()) {
        return Err(RouteTimeAnchorErrorV2::ThresholdNotMet);
    }
    Ok((evidence, signed.canonical_bytes()?))
}

fn authority_set_digest(authorities: &AuthoritySetV1, secp: &SecpContext) -> Result<Digest32> {
    validate_authorities(authorities, secp)?;
    let bytes = authorities
        .canonical_bytes()
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidAuthoritySet)?;
    digest_parts(AUTHORITY_SET_DOMAIN_V2, &[&bytes])
}

fn validate_authorities(authorities: &AuthoritySetV1, secp: &SecpContext) -> Result<()> {
    if authorities.xonly_keys().is_empty()
        || authorities.xonly_keys().len() > MAX_AUTHORITIES_V2
        || authorities.threshold() == 0
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(RouteTimeAnchorErrorV2::InvalidAuthoritySet);
    }
    authorities
        .validate_with_context(secp)
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidAuthoritySet)
}

fn validate_signature_shape(signatures: &[PreF6TimeSignatureV2]) -> Result<()> {
    if signatures.is_empty() || signatures.len() > MAX_AUTHORITIES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let mut previous = None;
    for signature in signatures {
        if previous.is_some_and(|index| index >= signature.signer_index) {
            return Err(RouteTimeAnchorErrorV2::InvalidSignature);
        }
        previous = Some(signature.signer_index);
    }
    Ok(())
}

fn encode_scope_request(request: PreF6TimeScopeRequestV2) -> Vec<u8> {
    let mut out = Vec::with_capacity(329);
    out.extend_from_slice(&request.network_id);
    out.extend_from_slice(&request.session_id);
    out.extend_from_slice(&request.route_id);
    out.extend_from_slice(&request.composition_id);
    out.extend_from_slice(&request.rfq_id);
    out.extend_from_slice(&request.negotiation_clock.chain_id.0);
    out.extend_from_slice(&request.negotiation_clock.profile_digest);
    out.extend_from_slice(&request.negotiation_clock.authority_scope);
    out.push(request.negotiation_clock.kind as u8);
    out.extend_from_slice(&request.registry_digest);
    out.extend_from_slice(&request.registry_epoch.to_be_bytes());
    out.extend_from_slice(&request.profile_bundle_digest);
    out
}

fn put_checkpoint(out: &mut Vec<u8>, checkpoint: PreF6CanonicalCheckpointV2) {
    out.extend_from_slice(&checkpoint.chain_id.0);
    out.extend_from_slice(&checkpoint.profile_digest);
    out.extend_from_slice(&checkpoint.genesis_hash);
    out.push(checkpoint.clock_kind as u8);
    out.extend_from_slice(&checkpoint.finalized_height.to_be_bytes());
    out.extend_from_slice(&checkpoint.finalized_hash);
    out.extend_from_slice(&checkpoint.finalized_parent_hash);
    out.extend_from_slice(&checkpoint.finalized_timestamp_seconds.to_be_bytes());
    out.extend_from_slice(&checkpoint.canonical_tip_height.to_be_bytes());
    out.extend_from_slice(&checkpoint.canonical_tip_hash);
    out.extend_from_slice(&checkpoint.canonicality_evidence_digest);
}

fn take_checkpoint(bytes: &[u8], cursor: &mut usize) -> Result<PreF6CanonicalCheckpointV2> {
    let chain_id = kaystra_core::types::ChainId(take_32(bytes, cursor)?);
    let profile_digest = take_32(bytes, cursor)?;
    let genesis_hash = take_32(bytes, cursor)?;
    let clock_kind = match take_u8(bytes, cursor)? {
        1 => NativeClockKindV2::BlockHeight,
        2 => NativeClockKindV2::TimestampSeconds,
        3 => NativeClockKindV2::BitcoinTime512,
        _ => return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding),
    };
    Ok(PreF6CanonicalCheckpointV2 {
        chain_id,
        profile_digest,
        genesis_hash,
        clock_kind,
        finalized_height: take_u64(bytes, cursor)?,
        finalized_hash: take_32(bytes, cursor)?,
        finalized_parent_hash: take_32(bytes, cursor)?,
        finalized_timestamp_seconds: take_u64(bytes, cursor)?,
        canonical_tip_height: take_u64(bytes, cursor)?,
        canonical_tip_hash: take_32(bytes, cursor)?,
        canonicality_evidence_digest: take_32(bytes, cursor)?,
    })
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32> {
    let mut state = Blake2bVar::new(32).map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
    state.update(domain);
    for part in parts {
        state.update(part);
    }
    let mut digest = [0; 32];
    state
        .finalize_variable(&mut digest)
        .map_err(|_| RouteTimeAnchorErrorV2::DigestFailure)?;
    if digest == ZERO_DIGEST {
        return Err(RouteTimeAnchorErrorV2::DigestFailure);
    }
    Ok(digest)
}

fn take_slice<'a>(bytes: &'a [u8], cursor: &mut usize, count: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(count)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
    *cursor = end;
    Ok(value)
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    let value = *bytes
        .get(*cursor)
        .ok_or(RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    let raw: [u8; 2] = take_slice(bytes, cursor, 2)?
        .try_into()
        .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
    Ok(u16::from_be_bytes(raw))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let raw: [u8; 4] = take_slice(bytes, cursor, 4)?
        .try_into()
        .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
    Ok(u32::from_be_bytes(raw))
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let raw: [u8; 8] = take_slice(bytes, cursor, 8)?
        .try_into()
        .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
    Ok(u64::from_be_bytes(raw))
}

fn take_32(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 32]> {
    take_slice(bytes, cursor, 32)?
        .try_into()
        .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)
}

fn take_64(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 64]> {
    take_slice(bytes, cursor, 64)?
        .try_into()
        .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)
}
