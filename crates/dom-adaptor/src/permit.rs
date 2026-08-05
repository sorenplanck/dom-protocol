//! Exact NAR-002 durable exposure-permit boundary.
#![allow(
    dead_code,
    reason = "parsed permits are records, while authorization capability remains crate-sealed"
)]

#[cfg(test)]
use crate::error::exact_array;
#[cfg(test)]
use crate::PurposeV1;
use crate::{AdaptorError, Result};
use dom_crypto::{blake2b_256_tagged, Hash256};

#[cfg(test)]
const PERMIT_DIGEST_TAG_V1: &str = "DOM:scriptless-vault-exposure-permit:v1";
const OUTBOUND_DIGEST_TAG_V1: &str = "DOM:scriptless-vault-outbound:v1";

/// Closed exposure-kind registry for independently authorized public artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExposureKindV1 {
    /// Canonical 35-byte nonce commitment.
    NonceCommitment = 0x01,
    /// Canonical 69-byte two-nonce reveal.
    NonceReveal = 0x02,
    /// Canonical 67-byte participant partial signature.
    PartialSignature = 0x03,
}

impl ExposureKindV1 {
    /// Return the exact registry byte.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Return the required canonical outbound artifact size.
    pub const fn outbound_len(self) -> usize {
        match self {
            Self::NonceCommitment => 35,
            Self::NonceReveal => 69,
            Self::PartialSignature => 67,
        }
    }
}

impl TryFrom<u8> for ExposureKindV1 {
    type Error = AdaptorError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::NonceCommitment),
            0x02 => Ok(Self::NonceReveal),
            0x03 => Ok(Self::PartialSignature),
            _ => Err(AdaptorError::InvalidContext("unknown exposure kind")),
        }
    }
}

/// Exact 252-byte one-shot permit issued after durable witness authorization.
///
/// The type intentionally implements no cloning, copying, debugging, display,
/// equality, ordering, or generic serialization.
#[cfg(test)]
pub(crate) struct ExposurePermitV1 {
    exposure_kind: ExposureKindV1,
    permit_id: [u8; 32],
    reservation_nonce_id: [u8; 32],
    session_id: [u8; 32],
    participant_id: [u8; 32],
    purpose: PurposeV1,
    template_hash: [u8; 32],
    outbound_digest: [u8; 32],
    epoch: u64,
    semantic_revision: u64,
    receipt_chain_hash: [u8; 32],
}

#[cfg(test)]
impl ExposurePermitV1 {
    /// Exact canonical encoded length.
    pub(crate) const ENCODED_LEN: usize = 252;
    /// Exact magic bytes.
    pub(crate) const MAGIC: [u8; 8] = *b"DOMEXPV1";
    /// Exact version.
    pub(crate) const VERSION: u16 = 1;

    /// Parse a permit issued by the durable G1b boundary.
    pub(crate) fn from_durable_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("ExposurePermitV1", bytes)?;
        if bytes[..8] != Self::MAGIC {
            return Err(AdaptorError::InvalidContext(
                "invalid exposure permit magic",
            ));
        }
        if u16::from_le_bytes([bytes[8], bytes[9]]) != Self::VERSION {
            return Err(AdaptorError::InvalidContext(
                "invalid exposure permit version",
            ));
        }
        let exposure_kind = ExposureKindV1::try_from(bytes[10])?;
        let permit = Self {
            exposure_kind,
            permit_id: exact_array::<32>("ExposurePermitV1 permit ID", &bytes[11..43])?,
            reservation_nonce_id: exact_array::<32>(
                "ExposurePermitV1 reservation nonce ID",
                &bytes[43..75],
            )?,
            session_id: exact_array::<32>("ExposurePermitV1 session ID", &bytes[75..107])?,
            participant_id: exact_array::<32>("ExposurePermitV1 participant ID", &bytes[107..139])?,
            purpose: PurposeV1::try_from(bytes[139])?,
            template_hash: exact_array::<32>("ExposurePermitV1 template hash", &bytes[140..172])?,
            outbound_digest: exact_array::<32>(
                "ExposurePermitV1 outbound digest",
                &bytes[172..204],
            )?,
            epoch: u64::from_le_bytes(exact_array::<8>(
                "ExposurePermitV1 epoch",
                &bytes[204..212],
            )?),
            semantic_revision: u64::from_le_bytes(exact_array::<8>(
                "ExposurePermitV1 semantic revision",
                &bytes[212..220],
            )?),
            receipt_chain_hash: exact_array::<32>(
                "ExposurePermitV1 receipt chain hash",
                &bytes[220..252],
            )?,
        };
        permit.purpose.require_strict_phase1()?;
        if permit.permit_id == [0; 32]
            || permit.reservation_nonce_id == [0; 32]
            || permit.session_id == [0; 32]
            || permit.participant_id == [0; 32]
            || permit.receipt_chain_hash == [0; 32]
        {
            return Err(AdaptorError::InvalidContext(
                "exposure permit identifiers and receipt hash must be nonzero",
            ));
        }
        Ok(permit)
    }

    /// Return exact canonical bytes for audit and digest verification.
    pub(crate) fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..8].copy_from_slice(&Self::MAGIC);
        bytes[8..10].copy_from_slice(&Self::VERSION.to_le_bytes());
        bytes[10] = self.exposure_kind.to_byte();
        bytes[11..43].copy_from_slice(&self.permit_id);
        bytes[43..75].copy_from_slice(&self.reservation_nonce_id);
        bytes[75..107].copy_from_slice(&self.session_id);
        bytes[107..139].copy_from_slice(&self.participant_id);
        bytes[139] = self.purpose.to_byte();
        bytes[140..172].copy_from_slice(&self.template_hash);
        bytes[172..204].copy_from_slice(&self.outbound_digest);
        bytes[204..212].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[212..220].copy_from_slice(&self.semantic_revision.to_le_bytes());
        bytes[220..].copy_from_slice(&self.receipt_chain_hash);
        bytes
    }

    /// Compute the assigned permit digest over all 252 bytes.
    pub(crate) fn digest(&self) -> Hash256 {
        blake2b_256_tagged(PERMIT_DIGEST_TAG_V1, &self.to_bytes())
    }

    pub(crate) const fn exposure_kind(&self) -> ExposureKindV1 {
        self.exposure_kind
    }
    pub(crate) const fn reservation_nonce_id(&self) -> &[u8; 32] {
        &self.reservation_nonce_id
    }
    pub(crate) const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    pub(crate) const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }
    pub(crate) const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }
    pub(crate) const fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }
    pub(crate) const fn outbound_digest(&self) -> &[u8; 32] {
        &self.outbound_digest
    }
}

/// Validate exact durable permit record bytes without creating an
/// authorization capability.
///
/// Parsing is intentionally separate from authorization. A successful result
/// does not grant access to any secret nonce or public artifact.
pub fn validate_exposure_permit_record_v1(bytes: &[u8]) -> Result<()> {
    crate::ExposurePermitBindingV1::from_persistence_bytes(bytes)
        .map(|_| ())
        .map_err(|_| AdaptorError::InvalidContext("invalid exposure permit record"))
}

/// Compute the exact digest bound into an exposure permit.
pub fn exposure_outbound_digest_v1(kind: ExposureKindV1, bytes: &[u8]) -> Result<Hash256> {
    if bytes.len() != kind.outbound_len() {
        return Err(AdaptorError::InvalidLength {
            object: "exposure outbound artifact",
            expected: kind.outbound_len(),
            actual: bytes.len(),
        });
    }
    let mut body = Vec::with_capacity(5 + bytes.len());
    body.push(kind.to_byte());
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(bytes);
    Ok(blake2b_256_tagged(OUTBOUND_DIGEST_TAG_V1, &body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permit_bytes() -> [u8; ExposurePermitV1::ENCODED_LEN] {
        let mut bytes = [0u8; ExposurePermitV1::ENCODED_LEN];
        bytes[..8].copy_from_slice(b"DOMEXPV1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10] = ExposureKindV1::NonceReveal.to_byte();
        bytes[11..43].fill(1);
        bytes[43..75].fill(2);
        bytes[75..107].fill(3);
        bytes[107..139].fill(4);
        bytes[139] = PurposeV1::Refund.to_byte();
        bytes[140..172].fill(5);
        bytes[172..204].fill(6);
        bytes[204..212].copy_from_slice(&7u64.to_le_bytes());
        bytes[212..220].copy_from_slice(&8u64.to_le_bytes());
        bytes[220..252].fill(9);
        bytes
    }

    #[test]
    fn permit_is_exact_and_closed() {
        let bytes = permit_bytes();
        let permit = ExposurePermitV1::from_durable_bytes(&bytes).expect("permit");
        assert_eq!(permit.to_bytes(), bytes);
        assert_ne!(permit.digest(), Hash256::ZERO);
        for length in 0..bytes.len() {
            assert!(ExposurePermitV1::from_durable_bytes(&bytes[..length]).is_err());
        }
        let mut unknown = bytes;
        unknown[10] = 4;
        assert!(ExposurePermitV1::from_durable_bytes(&unknown).is_err());
    }

    #[test]
    fn outbound_digest_binds_kind_length_and_bytes() {
        let bytes = [7u8; 69];
        let digest =
            exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &bytes).expect("digest");
        assert_ne!(digest, Hash256::ZERO);
        assert!(exposure_outbound_digest_v1(ExposureKindV1::NonceReveal, &bytes[..68]).is_err());
    }
}
