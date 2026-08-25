//! `SettlementTermsV1` — canonical terms, encoding and `terms_hash` (A3).
//!
//! Spec §6, DECIDED. This module IS the A3 ratification: the canonical wire
//! format (magic `DOMITRM1`, version 1, fixed field order, big-endian
//! integers) and the hash `BLAKE2b-256(TERMS_DOMAIN || canonical_bytes)`.
//! serde, JSON, CBOR or bincode never define this wire.
//!
//! Fail-closed rules (spec §6.1): the decoder accepts no trailing byte;
//! unknown version and unknown enum tags fail closed; no field is omitted
//! for having a zero value; `terms_hash` is not part of the structure
//! itself (no circularity).

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

use crate::types::*;

/// Leading magic of every canonical `SettlementTermsV1` encoding.
pub const TERMS_MAGIC: &[u8; 8] = b"DOMITRM1";
/// Frozen wire version. Any other version fails closed.
pub const TERMS_VERSION: u16 = 1;
/// Domain-separation prefix hashed before the canonical bytes.
pub const TERMS_DOMAIN: &[u8] = b"DOM-INTEROP/SETTLEMENT-TERMS/V1\0";
/// Hard bound on the opaque metadata field.
pub const MAX_METADATA_BYTES: usize = 4096;

/// The frozen terms of one DOM↔X settlement (spec §6.1).
///
/// `metadata` is opaque, bounded and economically non-authoritative: nothing
/// in it may ever influence a transition or an effect.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SettlementTermsV1 {
    /// One-shot public settlement identifier.
    pub settlement_id: SettlementId,
    /// One-shot public signing-session identifier.
    pub session_id: SessionId,
    /// Hash of the user intent this settlement executes.
    pub intent_hash: IntentHash,
    /// Solver that composed the settlement.
    pub solver_id: SolverId,
    /// The two participants, strictly sorted (`roster[0] < roster[1]`).
    pub roster: [ParticipantId; 2],
    /// The DOM leg (role MUST be [`LegRole::Dom`]).
    pub dom_leg: LegTermsV1,
    /// The counterparty leg (role MUST be [`LegRole::Counterparty`]).
    pub counterparty_leg: LegTermsV1,
    /// Adaptor point T, SEC1 compressed (prefix 0x02 or 0x03).
    pub adaptor_point_sec1: [u8; 33],
    /// Fee ceilings both parties accepted.
    pub fee_limit: FeeLimitV1,
    /// Recovery policy (refund-before-funding, evidence retention).
    pub recovery: RecoveryPolicyV1,
    /// Optional hash of the USPE assurance policy backing this settlement.
    pub assurance_policy_hash: Option<Digest32>,
    /// Version of the policy profile the fields above are read under.
    pub policy_version: u32,
    /// Opaque, bounded, economically non-authoritative metadata.
    pub metadata: Vec<u8>,
}

/// Validation and strict-decoding failures. Every variant is fail-closed:
/// no partially decoded or partially valid terms ever escape.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TermsError {
    /// Wire version is not [`TERMS_VERSION`].
    #[error("invalid version")]
    InvalidVersion,
    /// Leg roles are not (Dom, Counterparty) in that order.
    #[error("invalid topology")]
    InvalidTopology,
    /// Roster is not strictly sorted (equal entries are forbidden).
    #[error("invalid roster")]
    InvalidRoster,
    /// A leg amount is zero.
    #[error("zero amount")]
    ZeroAmount,
    /// `min_confirmations == 0` or `max_reorg_depth < min_confirmations`.
    #[error("invalid finality policy")]
    InvalidFinality,
    /// Metadata exceeds [`MAX_METADATA_BYTES`].
    #[error("metadata exceeds bound")]
    BoundsExceeded,
    /// Adaptor point is not SEC1 compressed (prefix 0x02/0x03).
    #[error("non-canonical adaptor point")]
    NonCanonicalPoint,
    /// The BLAKE2b-256 instance could not be initialized.
    #[error("hash initialization failed")]
    HashInitialization,
    /// Encoding does not start with [`TERMS_MAGIC`].
    #[error("invalid magic")]
    InvalidMagic,
    /// Encoding ends before the structure is complete.
    #[error("truncated encoding")]
    TruncatedEncoding,
    /// An enum/flag byte carries a tag outside its frozen set.
    #[error("unknown enum tag")]
    UnknownTag,
    /// Bytes remain after the structure is complete.
    #[error("trailing bytes")]
    TrailingBytes,
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

fn put_leg(out: &mut Vec<u8>, leg: &LegTermsV1) {
    out.push(leg.role as u8);
    out.extend_from_slice(&leg.chain_id.0);
    out.extend_from_slice(&leg.asset_id.0);
    put_u128(out, leg.amount);
    out.extend_from_slice(&leg.beneficiary.0);
    out.extend_from_slice(&leg.refund_to.0);
    out.push(leg.mechanism as u8);
    put_timelock(out, leg.deadline);
    put_u32(out, leg.finality.min_confirmations);
    put_u32(out, leg.finality.max_reorg_depth);
    out.extend_from_slice(&leg.adapter_profile_hash);
}

/// Strict big-endian cursor over one encoding. Every read is bounds-checked
/// and fails closed with [`TermsError::TruncatedEncoding`].
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TermsError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(TermsError::TruncatedEncoding)?;
        if end > self.bytes.len() {
            return Err(TermsError::TruncatedEncoding);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Fixed-size read. `take(N)` yields exactly N bytes or has already
    /// failed closed, so the copy below can never mismatch.
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], TermsError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, TermsError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, TermsError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, TermsError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, TermsError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_u128(&mut self) -> Result<u128, TermsError> {
        Ok(u128::from_be_bytes(self.take_array()?))
    }

    fn take_32(&mut self) -> Result<[u8; 32], TermsError> {
        self.take_array()
    }

    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn take_timelock(c: &mut Cursor<'_>) -> Result<TimelockSpec, TermsError> {
    let tag = c.take_u8()?;
    let value = c.take_u64()?;
    match tag {
        0x01 => Ok(TimelockSpec::BlockHeight { value }),
        0x02 => Ok(TimelockSpec::TimestampSeconds { value }),
        0x03 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(TermsError::UnknownTag),
    }
}

fn take_role(c: &mut Cursor<'_>) -> Result<LegRole, TermsError> {
    match c.take_u8()? {
        0x01 => Ok(LegRole::Dom),
        0x02 => Ok(LegRole::Counterparty),
        _ => Err(TermsError::UnknownTag),
    }
}

fn take_mechanism(c: &mut Cursor<'_>) -> Result<LockMechanism, TermsError> {
    match c.take_u8()? {
        0x01 => Ok(LockMechanism::DomAdaptor2of2),
        0x02 => Ok(LockMechanism::ConditionLock),
        0x03 => Ok(LockMechanism::SchnorrAdaptor),
        0x04 => Ok(LockMechanism::HashlockFallback),
        _ => Err(TermsError::UnknownTag),
    }
}

fn take_bool(c: &mut Cursor<'_>) -> Result<bool, TermsError> {
    match c.take_u8()? {
        0x00 => Ok(false),
        0x01 => Ok(true),
        _ => Err(TermsError::UnknownTag),
    }
}

fn take_leg(c: &mut Cursor<'_>) -> Result<LegTermsV1, TermsError> {
    Ok(LegTermsV1 {
        role: take_role(c)?,
        chain_id: ChainId(c.take_32()?),
        asset_id: AssetId(c.take_32()?),
        amount: c.take_u128()?,
        beneficiary: ParticipantId(c.take_32()?),
        refund_to: ParticipantId(c.take_32()?),
        mechanism: take_mechanism(c)?,
        deadline: take_timelock(c)?,
        finality: FinalityPolicyV1 {
            min_confirmations: c.take_u32()?,
            max_reorg_depth: c.take_u32()?,
        },
        adapter_profile_hash: c.take_32()?,
    })
}

impl SettlementTermsV1 {
    /// Checks the frozen validity rules (spec §6.1). Every canonical
    /// encoding — and every decoded value — passes through here.
    pub fn validate(&self) -> Result<(), TermsError> {
        if self.roster[0] >= self.roster[1] {
            return Err(TermsError::InvalidRoster);
        }
        if self.dom_leg.role != LegRole::Dom || self.counterparty_leg.role != LegRole::Counterparty
        {
            return Err(TermsError::InvalidTopology);
        }
        if self.dom_leg.amount == 0 || self.counterparty_leg.amount == 0 {
            return Err(TermsError::ZeroAmount);
        }
        for f in [self.dom_leg.finality, self.counterparty_leg.finality] {
            if f.min_confirmations == 0 || f.max_reorg_depth < f.min_confirmations {
                return Err(TermsError::InvalidFinality);
            }
        }
        if !matches!(self.adaptor_point_sec1[0], 0x02 | 0x03) {
            return Err(TermsError::NonCanonicalPoint);
        }
        if self.metadata.len() > MAX_METADATA_BYTES {
            return Err(TermsError::BoundsExceeded);
        }
        Ok(())
    }

    /// Canonical wire encoding: magic, version, fixed field order, all
    /// integers big-endian. Only valid terms encode.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TermsError> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    /// Encoding body behind [`Self::canonical_bytes`]. Never public:
    /// canonical bytes imply validity, so encoding always follows
    /// [`Self::validate`].
    fn encode_unchecked(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512 + self.metadata.len());
        out.extend_from_slice(TERMS_MAGIC);
        put_u16(&mut out, TERMS_VERSION);
        out.extend_from_slice(&self.settlement_id.0);
        out.extend_from_slice(&self.session_id.0);
        out.extend_from_slice(&self.intent_hash.0);
        out.extend_from_slice(&self.solver_id.0);
        out.extend_from_slice(&self.roster[0].0);
        out.extend_from_slice(&self.roster[1].0);
        put_leg(&mut out, &self.dom_leg);
        put_leg(&mut out, &self.counterparty_leg);
        out.extend_from_slice(&self.adaptor_point_sec1);
        put_u128(&mut out, self.fee_limit.dom_max);
        put_u128(&mut out, self.fee_limit.counterparty_max);
        out.push(u8::from(self.recovery.refund_before_funding));
        put_u64(&mut out, self.recovery.evidence_retention_blocks);
        match self.assurance_policy_hash {
            None => out.push(0x00),
            Some(h) => {
                out.push(0x01);
                out.extend_from_slice(&h);
            }
        }
        put_u32(&mut out, self.policy_version);
        put_u32(&mut out, self.metadata.len() as u32);
        out.extend_from_slice(&self.metadata);
        out
    }

    /// Strict decoder of the canonical wire (spec §6.1 fail-closed rules).
    ///
    /// Rejects, in decoding order: wrong magic, unknown version, any
    /// truncation, any enum/flag byte outside its frozen set, metadata
    /// beyond [`MAX_METADATA_BYTES`] (checked BEFORE allocating), trailing
    /// bytes — and then applies [`Self::validate`], so a decoded value obeys
    /// exactly the same rules as an encoded one.
    pub fn decode(bytes: &[u8]) -> Result<Self, TermsError> {
        let mut c = Cursor::new(bytes);
        if c.take(TERMS_MAGIC.len())? != TERMS_MAGIC {
            return Err(TermsError::InvalidMagic);
        }
        if c.take_u16()? != TERMS_VERSION {
            return Err(TermsError::InvalidVersion);
        }
        let settlement_id = SettlementId(c.take_32()?);
        let session_id = SessionId(c.take_32()?);
        let intent_hash = IntentHash(c.take_32()?);
        let solver_id = SolverId(c.take_32()?);
        let roster = [ParticipantId(c.take_32()?), ParticipantId(c.take_32()?)];
        let dom_leg = take_leg(&mut c)?;
        let counterparty_leg = take_leg(&mut c)?;
        let adaptor_point_sec1: [u8; 33] = c.take_array()?;
        let fee_limit = FeeLimitV1 {
            dom_max: c.take_u128()?,
            counterparty_max: c.take_u128()?,
        };
        let recovery = RecoveryPolicyV1 {
            refund_before_funding: take_bool(&mut c)?,
            evidence_retention_blocks: c.take_u64()?,
        };
        let assurance_policy_hash = match c.take_u8()? {
            0x00 => None,
            0x01 => Some(c.take_32()?),
            _ => return Err(TermsError::UnknownTag),
        };
        let policy_version = c.take_u32()?;
        let metadata_len = c.take_u32()? as usize;
        if metadata_len > MAX_METADATA_BYTES {
            return Err(TermsError::BoundsExceeded);
        }
        let metadata = c.take(metadata_len)?.to_vec();
        if !c.finished() {
            return Err(TermsError::TrailingBytes);
        }
        let terms = Self {
            settlement_id,
            session_id,
            intent_hash,
            solver_id,
            roster,
            dom_leg,
            counterparty_leg,
            adaptor_point_sec1,
            fee_limit,
            recovery,
            assurance_policy_hash,
            policy_version,
            metadata,
        };
        terms.validate()?;
        Ok(terms)
    }

    /// A3 authority hash: `BLAKE2b-256(TERMS_DOMAIN || canonical_bytes)`.
    pub fn terms_hash(&self) -> Result<Digest32, TermsError> {
        let encoded = self.canonical_bytes()?;
        let mut h = Blake2bVar::new(32).map_err(|_| TermsError::HashInitialization)?;
        h.update(TERMS_DOMAIN);
        h.update(&encoded);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out)
            .map_err(|_| TermsError::HashInitialization)?;
        Ok(out)
    }
}
