use btc_crypto::SecpContext;
use deployment_registry::{AuthoritySetV1, ResolvedRegistryV1};
use kaystra_core::terms::SettlementTermsV1;

use crate::codec::{MAX_EVIDENCE_BYTES_V2, MAX_POLICY_BYTES_V2};
use crate::types::{
    authority_set_digest_parts, RouteTimeEvidenceV2, RouteTimePolicyV2,
    MAX_TIME_ANCHOR_AUTHORITIES_V2,
};
use crate::{Result, RouteTimeAnchorErrorV2, ROUTE_TIME_VERSION_V2};

const SIGNED_POLICY_MAGIC_V2: &[u8; 8] = b"DOMRTSP2";
const SIGNED_EVIDENCE_MAGIC_V2: &[u8; 8] = b"DOMRTSE2";
const SIGNATURE_BYTES_V2: usize = 66;
pub(crate) const MAX_SIGNED_POLICY_BYTES_V2: usize =
    MAX_POLICY_BYTES_V2 + 8 + 2 + 2 + 4 + 2 + MAX_TIME_ANCHOR_AUTHORITIES_V2 * SIGNATURE_BYTES_V2;
pub(crate) const MAX_SIGNED_EVIDENCE_BYTES_V2: usize =
    MAX_EVIDENCE_BYTES_V2 + 8 + 2 + 2 + 4 + 2 + MAX_TIME_ANCHOR_AUTHORITIES_V2 * SIGNATURE_BYTES_V2;

/// One indexed BIP340 signature under an externally pinned authority set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeAnchorSignatureV2 {
    /// Index in the supplied policy or evidence authority set.
    pub signer_index: u16,
    /// Canonical 64-byte BIP340 signature.
    pub signature: [u8; 64],
}

/// Canonical policy bytes plus ordered threshold signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRouteTimePolicyV2 {
    policy_bytes: Vec<u8>,
    signatures: Vec<TimeAnchorSignatureV2>,
}

impl core::fmt::Debug for SignedRouteTimePolicyV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedRouteTimePolicyV2")
            .field("policy_bytes", &self.policy_bytes.len())
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

/// Canonical evidence bytes plus ordered threshold signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedRouteTimeEvidenceV2 {
    evidence_bytes: Vec<u8>,
    signatures: Vec<TimeAnchorSignatureV2>,
}

impl core::fmt::Debug for SignedRouteTimeEvidenceV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SignedRouteTimeEvidenceV2")
            .field("evidence_bytes", &self.evidence_bytes.len())
            .field("signature_count", &self.signatures.len())
            .finish()
    }
}

impl SignedRouteTimePolicyV2 {
    /// Wraps a canonical policy and a strictly ordered non-empty signature set.
    pub fn new(policy: &RouteTimePolicyV2, signatures: Vec<TimeAnchorSignatureV2>) -> Result<Self> {
        let value = Self {
            policy_bytes: policy.canonical_bytes()?,
            signatures,
        };
        validate_signature_shape(&value.signatures)?;
        Ok(value)
    }

    /// Exact canonical policy bytes covered by every signature.
    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }

    /// Ordered indexed signatures.
    pub fn signatures(&self) -> &[TimeAnchorSignatureV2] {
        &self.signatures
    }

    /// Strict canonical storage/transport bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        RouteTimePolicyV2::decode(&self.policy_bytes)?;
        encode_signed(
            SIGNED_POLICY_MAGIC_V2,
            &self.policy_bytes,
            &self.signatures,
            MAX_SIGNED_POLICY_BYTES_V2,
        )
    }

    /// Strictly decodes a signed policy and rejects alternate/trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (body, signatures) = decode_signed(
            SIGNED_POLICY_MAGIC_V2,
            bytes,
            MAX_POLICY_BYTES_V2,
            MAX_SIGNED_POLICY_BYTES_V2,
        )?;
        RouteTimePolicyV2::decode(&body)?;
        let value = Self {
            policy_bytes: body,
            signatures,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }

    pub(crate) fn verify(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        registry: &ResolvedRegistryV1,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
        now: u64,
    ) -> Result<RouteTimePolicyV2> {
        let policy = self.verify_authenticity(authorities, secp, registry, upstream, downstream)?;
        if now < policy.limits().valid_from_seconds || now >= policy.limits().expires_at_seconds {
            return Err(RouteTimeAnchorErrorV2::PolicyExpired);
        }
        Ok(policy)
    }

    pub(crate) fn verify_authenticity(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        registry: &ResolvedRegistryV1,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
    ) -> Result<RouteTimePolicyV2> {
        let policy = RouteTimePolicyV2::decode(&self.policy_bytes)?;
        policy.validate_against(registry, upstream, downstream)?;
        verify_signatures(
            authorities,
            secp,
            &policy.policy_digest()?,
            &self.signatures,
        )?;
        Ok(policy)
    }
}

impl SignedRouteTimeEvidenceV2 {
    /// Wraps canonical evidence and a strictly ordered non-empty signature set.
    pub fn new(
        evidence: &RouteTimeEvidenceV2,
        signatures: Vec<TimeAnchorSignatureV2>,
    ) -> Result<Self> {
        let value = Self {
            evidence_bytes: evidence.canonical_bytes()?,
            signatures,
        };
        validate_signature_shape(&value.signatures)?;
        Ok(value)
    }

    /// Exact canonical evidence bytes covered by every signature.
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }

    /// Ordered indexed signatures.
    pub fn signatures(&self) -> &[TimeAnchorSignatureV2] {
        &self.signatures
    }

    /// Strict canonical storage/transport bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        RouteTimeEvidenceV2::decode(&self.evidence_bytes)?;
        encode_signed(
            SIGNED_EVIDENCE_MAGIC_V2,
            &self.evidence_bytes,
            &self.signatures,
            MAX_SIGNED_EVIDENCE_BYTES_V2,
        )
    }

    /// Strictly decodes signed evidence and rejects alternate/trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (body, signatures) = decode_signed(
            SIGNED_EVIDENCE_MAGIC_V2,
            bytes,
            MAX_EVIDENCE_BYTES_V2,
            MAX_SIGNED_EVIDENCE_BYTES_V2,
        )?;
        RouteTimeEvidenceV2::decode(&body)?;
        let value = Self {
            evidence_bytes: body,
            signatures,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
        }
        Ok(value)
    }

    pub(crate) fn verify(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        policy: &RouteTimePolicyV2,
        now: u64,
    ) -> Result<RouteTimeEvidenceV2> {
        let evidence = self.verify_authenticity(authorities, secp, policy)?;
        evidence.validate_at(policy, now)?;
        Ok(evidence)
    }

    pub(crate) fn verify_authenticity(
        &self,
        authorities: &AuthoritySetV1,
        secp: &SecpContext,
        policy: &RouteTimePolicyV2,
    ) -> Result<RouteTimeEvidenceV2> {
        let evidence = RouteTimeEvidenceV2::decode(&self.evidence_bytes)?;
        evidence.validate_at(policy, evidence.observed_at_seconds())?;
        verify_signatures(
            authorities,
            secp,
            &evidence.evidence_digest()?,
            &self.signatures,
        )?;
        Ok(evidence)
    }
}

pub(crate) fn authority_set_digest(
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<[u8; 32]> {
    validate_authority_set(authorities, secp)?;
    authority_set_digest_parts(authorities.threshold(), authorities.xonly_keys())
}

fn verify_signatures(
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
    digest: &[u8; 32],
    signatures: &[TimeAnchorSignatureV2],
) -> Result<()> {
    validate_authority_set(authorities, secp)?;
    validate_signature_shape(signatures)?;
    for signature in signatures {
        let key = authorities
            .xonly_keys()
            .get(usize::from(signature.signer_index))
            .ok_or(RouteTimeAnchorErrorV2::InvalidSignature)?;
        secp.verify_bip340(key, digest, &signature.signature)
            .map_err(|_| RouteTimeAnchorErrorV2::InvalidSignature)?;
    }
    if signatures.len() < usize::from(authorities.threshold()) {
        return Err(RouteTimeAnchorErrorV2::ThresholdNotMet);
    }
    Ok(())
}

fn validate_authority_set(authorities: &AuthoritySetV1, secp: &SecpContext) -> Result<()> {
    if authorities.xonly_keys().is_empty()
        || authorities.xonly_keys().len() > MAX_TIME_ANCHOR_AUTHORITIES_V2
        || authorities.threshold() == 0
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(RouteTimeAnchorErrorV2::InvalidAuthoritySet);
    }
    authorities
        .validate_with_context(secp)
        .map_err(|_| RouteTimeAnchorErrorV2::InvalidAuthoritySet)
}

fn validate_signature_shape(signatures: &[TimeAnchorSignatureV2]) -> Result<()> {
    if signatures.is_empty() || signatures.len() > MAX_TIME_ANCHOR_AUTHORITIES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let mut previous: Option<u16> = None;
    for signature in signatures {
        if signature.signature == [0; 64]
            || previous
                .map(|index| signature.signer_index <= index)
                .unwrap_or(false)
        {
            return Err(RouteTimeAnchorErrorV2::InvalidSignature);
        }
        previous = Some(signature.signer_index);
    }
    Ok(())
}

fn encode_signed(
    magic: &[u8; 8],
    body: &[u8],
    signatures: &[TimeAnchorSignatureV2],
    maximum: usize,
) -> Result<Vec<u8>> {
    validate_signature_shape(signatures)?;
    let body_length =
        u32::try_from(body.len()).map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
    let signature_count =
        u16::try_from(signatures.len()).map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
    let mut output =
        Vec::with_capacity(8 + 2 + 2 + 4 + body.len() + 2 + signatures.len() * SIGNATURE_BYTES_V2);
    output.extend_from_slice(magic);
    output.extend_from_slice(&ROUTE_TIME_VERSION_V2.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&body_length.to_be_bytes());
    output.extend_from_slice(body);
    output.extend_from_slice(&signature_count.to_be_bytes());
    for signature in signatures {
        output.extend_from_slice(&signature.signer_index.to_be_bytes());
        output.extend_from_slice(&signature.signature);
    }
    if output.len() > maximum {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    Ok(output)
}

fn decode_signed(
    expected_magic: &[u8; 8],
    bytes: &[u8],
    maximum_body: usize,
    maximum_signed: usize,
) -> Result<(Vec<u8>, Vec<TimeAnchorSignatureV2>)> {
    if bytes.len() > maximum_signed {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let mut reader = SignedReaderV2::new(bytes);
    if reader.take::<8>()? != *expected_magic
        || reader.u16()? != ROUTE_TIME_VERSION_V2
        || reader.u16()? != 0
    {
        return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
    }
    let body_length =
        usize::try_from(reader.u32()?).map_err(|_| RouteTimeAnchorErrorV2::BoundExceeded)?;
    if body_length > maximum_body {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let body = reader.bytes(body_length)?.to_vec();
    let count = usize::from(reader.u16()?);
    if count == 0 || count > MAX_TIME_ANCHOR_AUTHORITIES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        signatures.push(TimeAnchorSignatureV2 {
            signer_index: reader.u16()?,
            signature: reader.take()?,
        });
    }
    reader.finish()?;
    validate_signature_shape(&signatures)?;
    Ok((body, signatures))
}

struct SignedReaderV2<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SignedReaderV2<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
        }
    }
}
