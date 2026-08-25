//! Normative assurance objects of the F4 specification §5 (D-017):
//! [`AssurancePolicyV1`], [`AssuranceCertificateV1`], their canonical wire
//! encodings and authority hashes.
//!
//! The codec follows the F2 §6.2 discipline exactly: leading magic, frozen
//! wire version, fixed field order, big-endian integers, `u8` tags for
//! enums, every length checked before allocation, strict decode that
//! fails closed on truncation, unknown tags and trailing bytes, and
//! `decode(encode(x)) == x` proven by vectors and property tests.
//!
//! Everything here is PUBLIC data: policies and certificates carry no
//! secret and grant nothing the chain does not already enforce (the
//! certificate is a record, not an authority — F4 spec §5.3).

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use counterparty_api::AdaptorPointBytes;
use kaystra_core::types::Digest32;

// Re-exported (not merely imported) so downstream F4 crates — §3.1 lists
// the harness — can name the field types through uspe without importing
// kaystra-core themselves.
pub use kaystra_core::state::EvidenceRefV1;
pub use kaystra_core::types::{AssetId, ChainId, SettlementId, TimelockSpec};

/// Leading magic of every canonical [`AssurancePolicyV1`] encoding.
pub const POLICY_MAGIC: &[u8; 8] = b"DOMIAPL1";
/// Frozen policy wire version. Any other version fails closed.
pub const POLICY_WIRE_VERSION: u16 = 1;
/// Frozen value of the [`AssurancePolicyV1::version`] field.
pub const POLICY_STRUCT_VERSION: u32 = 1;
/// Domain-separation prefix hashed before the canonical policy bytes.
pub const POLICY_DOMAIN: &[u8] = b"DOM-INTEROP/ASSURANCE-POLICY/V1\0";

/// Leading magic of every canonical [`AssuranceCertificateV1`] encoding.
pub const CERTIFICATE_MAGIC: &[u8; 8] = b"DOMIACT1";
/// Frozen certificate wire version. Any other version fails closed.
pub const CERTIFICATE_WIRE_VERSION: u16 = 1;
/// Domain-separation prefix hashed to derive the certificate id.
pub const CERTIFICATE_DOMAIN: &[u8] = b"DOM-INTEROP/ASSURANCE-CERTIFICATE/V1\0";

/// Public identifier of one assurance policy (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PolicyId(pub [u8; 32]);

/// Public identifier of one assurance certificate (32 bytes). Derived,
/// never chosen: see [`AssuranceCertificateV1::derive_certificate_id`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CertificateId(pub [u8; 32]);

/// Evidence classes a policy may require (F4 spec §8). Unimplemented
/// classes must refuse, never stub success (I13) — v1 has exactly one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvidenceRuleV1 {
    /// Valid failure evidence is a FINALIZED `Claimed` of a bound
    /// settlement leg revealing the canonical scalar for `adaptor_point`.
    RevealedScalarClaim {
        /// SEC1-compressed adaptor point `T = t*G` the claim must match.
        adaptor_point: AdaptorPointBytes,
    },
}

/// Resolution when no evidence is accepted within the deadline (F4 spec
/// §5.1). v1 has exactly one, and it is the conservative one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminalPolicyV1 {
    /// No accepted evidence within the deadline => the bond releases.
    ConservativeRelease,
}

/// The frozen assurance policy of one protected obligation (F4 spec §5.1).
///
/// Deadlines keep the bond chain's unit (`TimelockSpec`) and are never
/// silently converted (A4); [`Self::validate`] therefore requires all
/// four to live in the SAME domain, strictly increasing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssurancePolicyV1 {
    /// Public policy identifier.
    pub policy_id: PolicyId,
    /// Structure version; must equal [`POLICY_STRUCT_VERSION`].
    pub version: u32,
    /// The one settlement this policy protects (v1: one per policy).
    pub protected_settlement: SettlementId,
    /// Terms binding of the protected obligation.
    pub terms_hash: Digest32,
    /// Chain the bond lives on (32-byte registry id).
    pub bond_chain_id: ChainId,
    /// Asset of the bond (32-byte registry id).
    pub bond_asset: AssetId,
    /// Collateral the solver must lock, in the asset's smallest unit.
    pub required_collateral: u128,
    /// Ceiling on any compensation; `required_collateral` must not
    /// exceed it (the slash pays out the whole lock).
    pub compensation_cap: u128,
    /// `BondLocking` exit: uncertified collateral releases (D-F4.5).
    pub collateral_deadline: TimelockSpec,
    /// `ClaimWindow` exit.
    pub claim_deadline: TimelockSpec,
    /// `EvidenceVerification` exit.
    pub evidence_deadline: TimelockSpec,
    /// On-chain refund gate of the bond lock (F4 spec §7.2).
    pub bond_release_deadline: TimelockSpec,
    /// Evidence class that can slash under this policy.
    pub evidence_rule: EvidenceRuleV1,
    /// Resolution when the evidence deadline passes unmet.
    pub terminal_policy: TerminalPolicyV1,
}

/// The protection certificate (F4 spec §5.3). Its only origin is the
/// machine's `IssueCertificate` effect; it is data, not authority.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssuranceCertificateV1 {
    /// Digest of every other field — see
    /// [`Self::derive_certificate_id`]. A certificate whose id does not
    /// match its content is invalid.
    pub certificate_id: CertificateId,
    /// Protected settlement.
    pub settlement_id: SettlementId,
    /// Terms binding; divergence invalidates.
    pub terms_hash: Digest32,
    /// Policy the certificate was issued under.
    pub policy_id: PolicyId,
    /// `ConditionLockV2` lock id of the collateral.
    pub bond_lock_id: Digest32,
    /// The finalized `LockOpened` observation: no evidence, no issuance.
    pub collateral_evidence: EvidenceRefV1,
    /// Journal revision at issuance (audit anchor).
    pub issued_at_revision: u64,
    /// Certificate expiry, = the policy's `bond_release_deadline`.
    pub expires_at: TimelockSpec,
}

/// Validation and strict-decoding failures of the assurance objects.
/// Every variant is fail-closed: no partially decoded or partially valid
/// object ever escapes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AssuranceObjectError {
    /// Encoding does not start with the object's frozen magic.
    #[error("invalid magic")]
    InvalidMagic,
    /// Wire or structure version outside the frozen set.
    #[error("invalid version")]
    InvalidVersion,
    /// Encoding ends before the structure is complete.
    #[error("truncated encoding")]
    TruncatedEncoding,
    /// An enum/flag byte carries a tag outside its frozen set.
    #[error("unknown enum tag")]
    UnknownTag,
    /// Bytes remain after the structure is complete.
    #[error("trailing bytes")]
    TrailingBytes,
    /// `required_collateral` is zero: nothing would protect anything.
    #[error("zero collateral")]
    ZeroCollateral,
    /// `required_collateral` exceeds `compensation_cap`: the slash pays
    /// the whole lock, so such a policy could compensate over its cap.
    #[error("collateral exceeds the compensation cap")]
    CollateralExceedsCap,
    /// The adaptor point is not SEC1 compressed (prefix 0x02/0x03).
    #[error("non-canonical adaptor point")]
    NonCanonicalPoint,
    /// The four deadlines do not share one timelock domain. Comparing
    /// across domains would require a conversion, which A4 forbids.
    #[error("mixed deadline domains")]
    MixedDeadlineDomains,
    /// The deadlines are not strictly increasing
    /// (collateral < claim < evidence < bond release).
    #[error("non-monotonic deadlines")]
    NonMonotonicDeadlines,
    /// The certificate id does not match the digest of its content.
    #[error("certificate id does not bind its content")]
    CertificateIdMismatch,
    /// The BLAKE2b-256 instance could not be initialized.
    #[error("hash initialization failed")]
    HashInitialization,
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u128(out: &mut Vec<u8>, v: u128) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_timelock(out: &mut Vec<u8>, v: TimelockSpec) {
    match v {
        TimelockSpec::BlockHeight { value } => {
            out.push(0x01);
            put_u64(out, value);
        }
        TimelockSpec::TimestampSeconds { value } => {
            out.push(0x02);
            put_u64(out, value);
        }
        TimelockSpec::BtcTime512s { value } => {
            out.push(0x03);
            put_u64(out, value);
        }
    }
}

/// Strict big-endian cursor over one encoding. Every read is
/// bounds-checked and fails closed.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AssuranceObjectError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(AssuranceObjectError::TruncatedEncoding)?;
        if end > self.bytes.len() {
            return Err(AssuranceObjectError::TruncatedEncoding);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], AssuranceObjectError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, AssuranceObjectError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, AssuranceObjectError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, AssuranceObjectError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, AssuranceObjectError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_u128(&mut self) -> Result<u128, AssuranceObjectError> {
        Ok(u128::from_be_bytes(self.take_array()?))
    }

    fn take_32(&mut self) -> Result<[u8; 32], AssuranceObjectError> {
        self.take_array()
    }

    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn take_timelock(c: &mut Cursor<'_>) -> Result<TimelockSpec, AssuranceObjectError> {
    let tag = c.take_u8()?;
    let value = c.take_u64()?;
    match tag {
        0x01 => Ok(TimelockSpec::BlockHeight { value }),
        0x02 => Ok(TimelockSpec::TimestampSeconds { value }),
        0x03 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(AssuranceObjectError::UnknownTag),
    }
}

/// (domain tag, value) of a timelock, for same-domain monotonicity checks.
fn timelock_parts(v: TimelockSpec) -> (u8, u64) {
    match v {
        TimelockSpec::BlockHeight { value } => (0x01, value),
        TimelockSpec::TimestampSeconds { value } => (0x02, value),
        TimelockSpec::BtcTime512s { value } => (0x03, value),
    }
}

fn digest32(domain: &[u8], bytes: &[u8]) -> Result<Digest32, AssuranceObjectError> {
    let mut h = Blake2bVar::new(32).map_err(|_| AssuranceObjectError::HashInitialization)?;
    h.update(domain);
    h.update(bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out)
        .map_err(|_| AssuranceObjectError::HashInitialization)?;
    Ok(out)
}

impl AssurancePolicyV1 {
    /// Checks the frozen validity rules (F4 spec §5.1, §7.2). Every
    /// canonical encoding — and every decoded value — passes through
    /// here.
    pub fn validate(&self) -> Result<(), AssuranceObjectError> {
        if self.version != POLICY_STRUCT_VERSION {
            return Err(AssuranceObjectError::InvalidVersion);
        }
        if self.required_collateral == 0 {
            return Err(AssuranceObjectError::ZeroCollateral);
        }
        if self.required_collateral > self.compensation_cap {
            return Err(AssuranceObjectError::CollateralExceedsCap);
        }
        let EvidenceRuleV1::RevealedScalarClaim { adaptor_point } = &self.evidence_rule;
        if !matches!(adaptor_point.0[0], 0x02 | 0x03) {
            return Err(AssuranceObjectError::NonCanonicalPoint);
        }
        let parts = [
            timelock_parts(self.collateral_deadline),
            timelock_parts(self.claim_deadline),
            timelock_parts(self.evidence_deadline),
            timelock_parts(self.bond_release_deadline),
        ];
        if parts.iter().any(|(domain, _)| *domain != parts[0].0) {
            return Err(AssuranceObjectError::MixedDeadlineDomains);
        }
        if !parts.windows(2).all(|w| w[0].1 < w[1].1) {
            return Err(AssuranceObjectError::NonMonotonicDeadlines);
        }
        Ok(())
    }

    /// Canonical wire encoding: magic, wire version, fixed field order,
    /// all integers big-endian. Only valid policies encode.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AssuranceObjectError> {
        self.validate()?;
        let mut out = Vec::with_capacity(304);
        out.extend_from_slice(POLICY_MAGIC);
        put_u16(&mut out, POLICY_WIRE_VERSION);
        out.extend_from_slice(&self.policy_id.0);
        put_u32(&mut out, self.version);
        out.extend_from_slice(&self.protected_settlement.0);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.bond_chain_id.0);
        out.extend_from_slice(&self.bond_asset.0);
        put_u128(&mut out, self.required_collateral);
        put_u128(&mut out, self.compensation_cap);
        put_timelock(&mut out, self.collateral_deadline);
        put_timelock(&mut out, self.claim_deadline);
        put_timelock(&mut out, self.evidence_deadline);
        put_timelock(&mut out, self.bond_release_deadline);
        let EvidenceRuleV1::RevealedScalarClaim { adaptor_point } = &self.evidence_rule;
        out.push(0x01);
        out.extend_from_slice(&adaptor_point.0);
        let TerminalPolicyV1::ConservativeRelease = self.terminal_policy;
        out.push(0x01);
        Ok(out)
    }

    /// Strict decoder of the canonical wire. Rejects, in decoding order:
    /// wrong magic, unknown version, any truncation, any enum tag outside
    /// its frozen set, trailing bytes — then applies [`Self::validate`],
    /// so a decoded value obeys exactly the same rules as an encoded one.
    pub fn decode(bytes: &[u8]) -> Result<Self, AssuranceObjectError> {
        let mut c = Cursor::new(bytes);
        if c.take(POLICY_MAGIC.len())? != POLICY_MAGIC {
            return Err(AssuranceObjectError::InvalidMagic);
        }
        if c.take_u16()? != POLICY_WIRE_VERSION {
            return Err(AssuranceObjectError::InvalidVersion);
        }
        let policy_id = PolicyId(c.take_32()?);
        let version = c.take_u32()?;
        let protected_settlement = SettlementId(c.take_32()?);
        let terms_hash = c.take_32()?;
        let bond_chain_id = ChainId(c.take_32()?);
        let bond_asset = AssetId(c.take_32()?);
        let required_collateral = c.take_u128()?;
        let compensation_cap = c.take_u128()?;
        let collateral_deadline = take_timelock(&mut c)?;
        let claim_deadline = take_timelock(&mut c)?;
        let evidence_deadline = take_timelock(&mut c)?;
        let bond_release_deadline = take_timelock(&mut c)?;
        let evidence_rule = match c.take_u8()? {
            0x01 => EvidenceRuleV1::RevealedScalarClaim {
                adaptor_point: AdaptorPointBytes(c.take_array()?),
            },
            _ => return Err(AssuranceObjectError::UnknownTag),
        };
        let terminal_policy = match c.take_u8()? {
            0x01 => TerminalPolicyV1::ConservativeRelease,
            _ => return Err(AssuranceObjectError::UnknownTag),
        };
        if !c.finished() {
            return Err(AssuranceObjectError::TrailingBytes);
        }
        let policy = Self {
            policy_id,
            version,
            protected_settlement,
            terms_hash,
            bond_chain_id,
            bond_asset,
            required_collateral,
            compensation_cap,
            collateral_deadline,
            claim_deadline,
            evidence_deadline,
            bond_release_deadline,
            evidence_rule,
            terminal_policy,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Authority hash of the policy:
    /// `BLAKE2b-256(POLICY_DOMAIN || canonical_bytes)`. This is the value
    /// `SettlementTermsV1.assurance_policy_hash` carries when the
    /// settlement is protected (F4 spec §5.2).
    pub fn policy_hash(&self) -> Result<Digest32, AssuranceObjectError> {
        digest32(POLICY_DOMAIN, &self.canonical_bytes()?)
    }
}

impl AssuranceCertificateV1 {
    /// Issues a certificate: derives the binding id over the given
    /// content and validates. The machine's `IssueCertificate` effect is
    /// the ONLY legitimate caller in production.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        settlement_id: SettlementId,
        terms_hash: Digest32,
        policy_id: PolicyId,
        bond_lock_id: Digest32,
        collateral_evidence: EvidenceRefV1,
        issued_at_revision: u64,
        expires_at: TimelockSpec,
    ) -> Result<Self, AssuranceObjectError> {
        let mut certificate = Self {
            certificate_id: CertificateId([0u8; 32]),
            settlement_id,
            terms_hash,
            policy_id,
            bond_lock_id,
            collateral_evidence,
            issued_at_revision,
            expires_at,
        };
        certificate.certificate_id = certificate.derive_certificate_id()?;
        certificate.validate()?;
        Ok(certificate)
    }

    /// Canonical encoding of every field EXCEPT the certificate id, in
    /// wire order. The id is the digest of exactly these bytes.
    fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(CERTIFICATE_MAGIC);
        put_u16(&mut out, CERTIFICATE_WIRE_VERSION);
        out.extend_from_slice(&self.settlement_id.0);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.policy_id.0);
        out.extend_from_slice(&self.bond_lock_id);
        out.extend_from_slice(&self.collateral_evidence.chain_id.0);
        out.extend_from_slice(&self.collateral_evidence.tx_id);
        put_u32(&mut out, self.collateral_evidence.event_index);
        put_u64(&mut out, self.collateral_evidence.block_height);
        out.extend_from_slice(&self.collateral_evidence.block_anchor);
        put_u64(&mut out, self.issued_at_revision);
        put_timelock(&mut out, self.expires_at);
        out
    }

    /// `BLAKE2b-256(CERTIFICATE_DOMAIN || body_bytes)`: the id a
    /// certificate with this content MUST carry.
    pub fn derive_certificate_id(&self) -> Result<CertificateId, AssuranceObjectError> {
        Ok(CertificateId(digest32(
            CERTIFICATE_DOMAIN,
            &self.body_bytes(),
        )?))
    }

    /// A certificate is valid iff its id is the digest of its content.
    /// Any tampered field breaks the binding.
    pub fn validate(&self) -> Result<(), AssuranceObjectError> {
        if self.certificate_id != self.derive_certificate_id()? {
            return Err(AssuranceObjectError::CertificateIdMismatch);
        }
        Ok(())
    }

    /// Canonical wire encoding: magic, wire version, certificate id,
    /// then the body fields in [`Self::body_bytes`] order. Only valid
    /// certificates encode.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AssuranceObjectError> {
        self.validate()?;
        let body = self.body_bytes();
        let mut out = Vec::with_capacity(body.len() + 32);
        out.extend_from_slice(&body[..POLICY_MAGIC.len() + 2]);
        out.extend_from_slice(&self.certificate_id.0);
        out.extend_from_slice(&body[POLICY_MAGIC.len() + 2..]);
        Ok(out)
    }

    /// Strict decoder of the canonical wire; same fail-closed rules as
    /// the policy decoder, plus the id-binding check.
    pub fn decode(bytes: &[u8]) -> Result<Self, AssuranceObjectError> {
        let mut c = Cursor::new(bytes);
        if c.take(CERTIFICATE_MAGIC.len())? != CERTIFICATE_MAGIC {
            return Err(AssuranceObjectError::InvalidMagic);
        }
        if c.take_u16()? != CERTIFICATE_WIRE_VERSION {
            return Err(AssuranceObjectError::InvalidVersion);
        }
        let certificate_id = CertificateId(c.take_32()?);
        let settlement_id = SettlementId(c.take_32()?);
        let terms_hash = c.take_32()?;
        let policy_id = PolicyId(c.take_32()?);
        let bond_lock_id = c.take_32()?;
        let collateral_evidence = EvidenceRefV1 {
            chain_id: ChainId(c.take_32()?),
            tx_id: c.take_32()?,
            event_index: c.take_u32()?,
            block_height: c.take_u64()?,
            block_anchor: c.take_32()?,
        };
        let issued_at_revision = c.take_u64()?;
        let expires_at = take_timelock(&mut c)?;
        if !c.finished() {
            return Err(AssuranceObjectError::TrailingBytes);
        }
        let certificate = Self {
            certificate_id,
            settlement_id,
            terms_hash,
            policy_id,
            bond_lock_id,
            collateral_evidence,
            issued_at_revision,
            expires_at,
        };
        certificate.validate()?;
        Ok(certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }

    fn point(prefix: u8) -> AdaptorPointBytes {
        let mut p = [0xe1u8; 33];
        p[0] = prefix;
        AdaptorPointBytes(p)
    }

    fn sample_policy() -> AssurancePolicyV1 {
        AssurancePolicyV1 {
            policy_id: PolicyId(b32(0x10)),
            version: POLICY_STRUCT_VERSION,
            protected_settlement: SettlementId(b32(0x20)),
            terms_hash: b32(0x30),
            bond_chain_id: ChainId(b32(0x40)),
            bond_asset: AssetId(b32(0x50)),
            required_collateral: 700,
            compensation_cap: 1_000,
            collateral_deadline: TimelockSpec::TimestampSeconds { value: 1_000 },
            claim_deadline: TimelockSpec::TimestampSeconds { value: 2_000 },
            evidence_deadline: TimelockSpec::TimestampSeconds { value: 3_000 },
            bond_release_deadline: TimelockSpec::TimestampSeconds { value: 4_000 },
            evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
                adaptor_point: point(0x02),
            },
            terminal_policy: TerminalPolicyV1::ConservativeRelease,
        }
    }

    fn sample_evidence() -> EvidenceRefV1 {
        EvidenceRefV1 {
            chain_id: ChainId(b32(0x40)),
            tx_id: b32(0x60),
            event_index: 3,
            block_height: 77,
            block_anchor: b32(0x70),
        }
    }

    fn sample_certificate() -> AssuranceCertificateV1 {
        AssuranceCertificateV1::issue(
            SettlementId(b32(0x20)),
            b32(0x30),
            PolicyId(b32(0x10)),
            b32(0x80),
            sample_evidence(),
            9,
            TimelockSpec::TimestampSeconds { value: 4_000 },
        )
        .unwrap()
    }

    #[test]
    fn policy_roundtrip_is_the_identity() {
        let policy = sample_policy();
        let bytes = policy.canonical_bytes().unwrap();
        assert_eq!(AssurancePolicyV1::decode(&bytes).unwrap(), policy);
    }

    #[test]
    fn certificate_roundtrip_is_the_identity() {
        let certificate = sample_certificate();
        let bytes = certificate.canonical_bytes().unwrap();
        assert_eq!(AssuranceCertificateV1::decode(&bytes).unwrap(), certificate);
    }

    /// Frozen vectors: the canonical encoding lengths and the authority
    /// hashes of the samples above. A codec change that alters any byte
    /// breaks these on purpose.
    #[test]
    fn frozen_vectors_hold() {
        let policy = sample_policy();
        let bytes = policy.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 277);
        assert_eq!(&bytes[..10], b"DOMIAPL1\x00\x01");
        assert_eq!(
            hex(&policy.policy_hash().unwrap()),
            "1c06d34205616922ba7184d9eae6fc7f8db5e54aebdbbd1273cd338df3ded517",
        );

        let certificate = sample_certificate();
        let cert_bytes = certificate.canonical_bytes().unwrap();
        assert_eq!(cert_bytes.len(), 295);
        assert_eq!(&cert_bytes[..10], b"DOMIACT1\x00\x01");
        assert_eq!(
            hex(&certificate.certificate_id.0),
            "884d503070015c17b56ac2bccbe2e18cf91f82fc67d7314808db7562b0307730",
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn zero_collateral_is_refused() {
        let mut policy = sample_policy();
        policy.required_collateral = 0;
        assert_eq!(
            policy.validate().unwrap_err(),
            AssuranceObjectError::ZeroCollateral
        );
    }

    #[test]
    fn collateral_over_cap_is_refused() {
        let mut policy = sample_policy();
        policy.required_collateral = policy.compensation_cap + 1;
        assert_eq!(
            policy.validate().unwrap_err(),
            AssuranceObjectError::CollateralExceedsCap
        );
        assert!(policy.canonical_bytes().is_err(), "invalid must not encode");
    }

    #[test]
    fn non_canonical_point_is_refused() {
        for prefix in [0x00, 0x04, 0xff] {
            let mut policy = sample_policy();
            policy.evidence_rule = EvidenceRuleV1::RevealedScalarClaim {
                adaptor_point: point(prefix),
            };
            assert_eq!(
                policy.validate().unwrap_err(),
                AssuranceObjectError::NonCanonicalPoint
            );
        }
    }

    #[test]
    fn mixed_deadline_domains_are_refused() {
        let mut policy = sample_policy();
        policy.claim_deadline = TimelockSpec::BlockHeight { value: 2_000 };
        assert_eq!(
            policy.validate().unwrap_err(),
            AssuranceObjectError::MixedDeadlineDomains
        );
    }

    #[test]
    fn non_monotonic_deadlines_are_refused() {
        // Equal adjacent deadlines are refused too: the slash-execution
        // margin (spec §7.2) is never zero.
        for (a, b) in [(2_000, 2_000), (3_000, 2_500)] {
            let mut policy = sample_policy();
            policy.claim_deadline = TimelockSpec::TimestampSeconds { value: a };
            policy.evidence_deadline = TimelockSpec::TimestampSeconds { value: b };
            assert_eq!(
                policy.validate().unwrap_err(),
                AssuranceObjectError::NonMonotonicDeadlines
            );
        }
    }

    #[test]
    fn wrong_struct_version_is_refused() {
        let mut policy = sample_policy();
        policy.version = 2;
        assert_eq!(
            policy.validate().unwrap_err(),
            AssuranceObjectError::InvalidVersion
        );
    }

    #[test]
    fn decode_rejects_magic_version_truncation_and_trailing() {
        let bytes = sample_policy().canonical_bytes().unwrap();

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 0x01;
        assert_eq!(
            AssurancePolicyV1::decode(&wrong_magic).unwrap_err(),
            AssuranceObjectError::InvalidMagic
        );

        let mut wrong_version = bytes.clone();
        wrong_version[9] ^= 0x01;
        assert_eq!(
            AssurancePolicyV1::decode(&wrong_version).unwrap_err(),
            AssuranceObjectError::InvalidVersion
        );

        for cut in [0, 1, 9, 10, bytes.len() - 1] {
            assert_eq!(
                AssurancePolicyV1::decode(&bytes[..cut]).unwrap_err(),
                AssuranceObjectError::TruncatedEncoding,
                "prefix of {cut} bytes must be truncated"
            );
        }

        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            AssurancePolicyV1::decode(&trailing).unwrap_err(),
            AssuranceObjectError::TrailingBytes
        );
    }

    #[test]
    fn decode_rejects_unknown_tags() {
        let policy = sample_policy();
        let bytes = policy.canonical_bytes().unwrap();
        // The evidence-rule tag sits right after the four timelocks.
        let rule_tag_at = bytes.len() - 1 - 33 - 1;
        assert_eq!(bytes[rule_tag_at], 0x01);
        let mut bad_rule = bytes.clone();
        bad_rule[rule_tag_at] = 0x7f;
        assert_eq!(
            AssurancePolicyV1::decode(&bad_rule).unwrap_err(),
            AssuranceObjectError::UnknownTag
        );
        let mut bad_terminal = bytes.clone();
        *bad_terminal.last_mut().unwrap() = 0x7f;
        assert_eq!(
            AssurancePolicyV1::decode(&bad_terminal).unwrap_err(),
            AssuranceObjectError::UnknownTag
        );
    }

    #[test]
    fn certificate_id_binds_every_field() {
        let mut tampered = sample_certificate();
        tampered.terms_hash[0] ^= 0x01;
        assert_eq!(
            tampered.validate().unwrap_err(),
            AssuranceObjectError::CertificateIdMismatch
        );
        assert!(tampered.canonical_bytes().is_err());

        let mut wrong_id = sample_certificate();
        wrong_id.certificate_id.0[0] ^= 0x01;
        assert_eq!(
            wrong_id.validate().unwrap_err(),
            AssuranceObjectError::CertificateIdMismatch
        );
    }

    #[test]
    fn certificate_decode_rejects_any_single_byte_flip() {
        // The id is a digest of the content, so no single-byte corruption
        // of the wire may ever yield a valid certificate.
        let bytes = sample_certificate().canonical_bytes().unwrap();
        for i in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[i] ^= 0x01;
            assert!(
                AssuranceCertificateV1::decode(&flipped).is_err(),
                "byte {i} flipped and the certificate still decoded"
            );
        }
    }

    #[test]
    fn policy_hash_is_domain_separated_and_content_bound() {
        let policy = sample_policy();
        let h = policy.policy_hash().unwrap();
        let mut other = policy;
        other.compensation_cap += 1;
        assert_ne!(h, other.policy_hash().unwrap());
        // The hash is not the bare BLAKE2 of the bytes: the domain prefix
        // participates.
        let bare = {
            use blake2::digest::{Update, VariableOutput};
            let mut hasher = blake2::Blake2bVar::new(32).unwrap();
            hasher.update(&policy.canonical_bytes().unwrap());
            let mut out = [0u8; 32];
            hasher.finalize_variable(&mut out).unwrap();
            out
        };
        assert_ne!(h, bare);
    }
}
