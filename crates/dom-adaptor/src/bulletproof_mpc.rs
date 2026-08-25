//! Canonical public codecs for collaborative DOM Bulletproof V1.
#![allow(
    dead_code,
    reason = "ratified one-shot backend phases remain crate-sealed until Phase 2 orchestration"
)]

use crate::{error::exact_array, AdaptorError, Result, TrustedChainIdV1};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{
    blake2b_256_tagged, bulletproof_mpc_aggregate_tau_x, bulletproof_mpc_finalize,
    bulletproof_mpc_finalize_continuation_from_bytes_v1,
    bulletproof_mpc_finalize_continuation_to_bytes_v1, bulletproof_mpc_round1,
    bulletproof_mpc_round2, h_compressed, scalar_bytes_are_canonical, scalar_from_wide_be,
    scriptless_add_public_points, BlindingFactor, BulletproofMpcFinalizeState,
    BulletproofMpcRound1State, PublicKey, MAX_PROVABLE_VALUE,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const STATEMENT_TAG_V1: &str = crate::DomainTag::BpStatement.as_str();
const NO_RECOVERY_TAG_V1: &str = crate::DomainTag::BpNoRecovery.as_str();
const COMMON_COMMIT_TAG_V1: &str = crate::DomainTag::BpCommonCommit.as_str();
const COMMON_JOINT_TAG_V1: &str = crate::DomainTag::BpCommonJoint.as_str();
const COMMON_NONCE_TAG_V1: &str = crate::DomainTag::BpCommonNonce.as_str();
const ROUND1_COMMIT_TAG_V1: &str = crate::DomainTag::BpRound1Commit.as_str();
const STATEMENT_MAGIC: &[u8; 4] = b"DSBP";
const ROUND1_MAGIC: &[u8; 4] = b"DBR1";
const ROUND2_MAGIC: &[u8; 4] = b"DBR2";
const VERSION: u16 = 1;

/// Exact variable-length statement for one collaborative DOM Bulletproof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpStatementV1 {
    bytes: Vec<u8>,
    participant_ids: Vec<[u8; 32]>,
    commitment_shares: Vec<PublicKey>,
    aggregate_commitment: PublicKey,
    value_noms: u64,
    recovery_binding_hash: [u8; 32],
}

impl BpStatementV1 {
    /// Minimum participant count.
    pub const MIN_PARTICIPANTS: usize = 2;
    /// Maximum participant count.
    pub const MAX_PARTICIPANTS: usize = 16;

    /// §4.3 aggregate commitment `C = v*H + Σ R_i` over the ordered pure
    /// blinding shares `R_i = r_i*G` (§4.2).
    ///
    /// Each published share is the pure point `R_i`, exactly the point party `i`
    /// proves knowledge of in its §4.2 share PoK; the value term `v*H` is added
    /// once, on top of the ordered point sum. The value term is formed without
    /// ever taking a zero blinding — `(v*H + b*G) - (b*G)` for a fixed nonzero
    /// `b` — and the shares are summed as points, never reduced to a scalar
    /// (§1.2). This is the exact `aggregate_commitment` the frozen statement
    /// carries, so both parties derive the same `C` from the same shares.
    pub fn aggregate_commitment_from_shares(
        shares: &[PublicKey],
        value_noms: u64,
    ) -> Result<PublicKey> {
        // §4.3: R_total = Σ R_i (point addition; rejects the identity).
        let r_total = scriptless_add_public_points(shares)?;
        let r_total_commitment = Commitment::from_compressed_bytes(&r_total.to_compressed_bytes())
            .map_err(|_| AdaptorError::InvalidContext("aggregate R_total is not a valid point"))?;
        // §4.3: C = v*H + R_total, rejecting only R_total or C at infinity —
        // not the v*H term itself. When v = 0 the value term is the identity
        // and C = R_total; §4.3 permits that (the §5.7 v=0 edge), so it is not
        // an error. For v != 0, v*H is formed without a zero blinding:
        // (v*H + b*G) - (b*G) for a fixed nonzero b (commit rejects a zero
        // blinding), then added to the ordered point sum.
        let commitment = if value_noms == 0 {
            r_total_commitment
        } else {
            let base = BlindingFactor::from_bytes([
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
            .map_err(|_| {
                AdaptorError::InvalidContext("fixed value-generator blinding is invalid")
            })?;
            let value_h = Commitment::commit(value_noms, &base)
                .sub(&Commitment::commit(0, &base))
                .map_err(|_| {
                    AdaptorError::InvalidContext("value generator term is the identity")
                })?;
            value_h
                .add(&r_total_commitment)
                .map_err(|_| AdaptorError::InvalidContext("shared commitment is the identity"))?
        };
        PublicKey::from_compressed_bytes(commitment.as_bytes())
            .map_err(|_| AdaptorError::InvalidContext("aggregate commitment is not a valid point"))
    }

    /// Construct an exact statement from authenticated public inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: &TrustedChainIdV1,
        session_id: [u8; 32],
        participant_ids: Vec<[u8; 32]>,
        value_noms: u64,
        commitment_shares: Vec<PublicKey>,
        aggregate_commitment: PublicKey,
        recovery_binding_hash: Option<[u8; 32]>,
    ) -> Result<Self> {
        validate_participants(&participant_ids)?;
        if chain_id.as_bytes() == &[0u8; 32] || session_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof chain and session IDs must be nonzero",
            ));
        }
        if value_noms > MAX_PROVABLE_VALUE {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof value exceeds MAX_PROVABLE_VALUE",
            ));
        }
        if commitment_shares.len() != participant_ids.len() {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof commitment-share count differs from participant count",
            ));
        }
        validate_aggregate(&commitment_shares, &aggregate_commitment, value_noms)?;
        let recovery_binding_hash = match recovery_binding_hash {
            Some(hash) => hash,
            None => *blake2b_256_tagged(NO_RECOVERY_TAG_V1, &[]).as_bytes(),
        };
        if recovery_binding_hash == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof recovery binding hash must be nonzero",
            ));
        }

        let mut bytes = Vec::with_capacity(187 + 65 * participant_ids.len());
        bytes.extend_from_slice(STATEMENT_MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(chain_id.as_bytes());
        bytes.extend_from_slice(&session_id);
        bytes.push(participant_ids.len() as u8);
        for participant in &participant_ids {
            bytes.extend_from_slice(participant);
        }
        bytes.extend_from_slice(&value_noms.to_le_bytes());
        bytes.extend_from_slice(&MAX_PROVABLE_VALUE.to_le_bytes());
        bytes.extend_from_slice(&h_compressed()?);
        bytes.push(commitment_shares.len() as u8);
        for commitment in &commitment_shares {
            bytes.extend_from_slice(&commitment.to_compressed_bytes());
        }
        bytes.extend_from_slice(&aggregate_commitment.to_compressed_bytes());
        bytes.extend_from_slice(&recovery_binding_hash);
        bytes.push(64);
        debug_assert_eq!(bytes.len(), 187 + 65 * participant_ids.len());
        Ok(Self {
            bytes,
            participant_ids,
            commitment_shares,
            aggregate_commitment,
            value_noms,
            recovery_binding_hash,
        })
    }

    /// Parse exact canonical statement bytes and validate every derived field.
    pub fn from_bytes(bytes: &[u8], trusted_chain_id: &TrustedChainIdV1) -> Result<Self> {
        if bytes.len() < 317 {
            return Err(AdaptorError::InvalidLength {
                object: "BpStatementV1",
                expected: 317,
                actual: bytes.len(),
            });
        }
        if &bytes[..4] != STATEMENT_MAGIC {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof statement magic mismatch",
            ));
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof statement version must be exactly V1",
            ));
        }
        if bytes[6..38] != *trusted_chain_id.as_bytes() {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof chain ID differs from the trusted local chain",
            ));
        }
        if bytes[38..70] == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof chain and session IDs must be nonzero",
            ));
        }
        let count = usize::from(bytes[70]);
        if !(Self::MIN_PARTICIPANTS..=Self::MAX_PARTICIPANTS).contains(&count) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof participant count must be 2 through 16",
            ));
        }
        let expected = 187 + 65 * count;
        if bytes.len() != expected {
            return Err(AdaptorError::InvalidLength {
                object: "BpStatementV1",
                expected,
                actual: bytes.len(),
            });
        }
        let mut cursor = 71;
        let mut participant_ids = Vec::with_capacity(count);
        for _ in 0..count {
            participant_ids.push(exact_array::<32>(
                "BpStatementV1 participant ID",
                &bytes[cursor..cursor + 32],
            )?);
            cursor += 32;
        }
        validate_participants(&participant_ids)?;
        let value_noms = u64::from_le_bytes(exact_array::<8>(
            "BpStatementV1 value",
            &bytes[cursor..cursor + 8],
        )?);
        cursor += 8;
        let maximum = u64::from_le_bytes(exact_array::<8>(
            "BpStatementV1 maximum",
            &bytes[cursor..cursor + 8],
        )?);
        cursor += 8;
        if value_noms > MAX_PROVABLE_VALUE || maximum != MAX_PROVABLE_VALUE {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof value bounds differ from the frozen profile",
            ));
        }
        if bytes[cursor..cursor + 33] != h_compressed()? {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof value generator differs from H_DOM",
            ));
        }
        cursor += 33;
        if usize::from(bytes[cursor]) != count {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof commitment-share count differs from participant count",
            ));
        }
        cursor += 1;
        let mut commitment_shares = Vec::with_capacity(count);
        for _ in 0..count {
            commitment_shares.push(PublicKey::from_compressed_bytes(
                &bytes[cursor..cursor + 33],
            )?);
            cursor += 33;
        }
        let aggregate_commitment = PublicKey::from_compressed_bytes(&bytes[cursor..cursor + 33])?;
        cursor += 33;
        validate_aggregate(&commitment_shares, &aggregate_commitment, value_noms)?;
        if bytes[cursor..cursor + 32] == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof recovery binding hash must be nonzero",
            ));
        }
        cursor += 32;
        if bytes[cursor] != 64 {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof proof width must be 64 bits",
            ));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            participant_ids,
            commitment_shares,
            aggregate_commitment,
            value_noms,
            recovery_binding_hash: exact_array::<32>(
                "BpStatementV1 recovery binding hash",
                &bytes[cursor - 32..cursor],
            )?,
        })
    }

    /// Return the exact statement bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the authoritative statement hash.
    pub fn statement_hash(&self) -> [u8; 32] {
        *blake2b_256_tagged(STATEMENT_TAG_V1, &self.bytes).as_bytes()
    }

    /// Return the authenticated participant roster.
    pub fn participant_ids(&self) -> &[[u8; 32]] {
        &self.participant_ids
    }

    /// Return the ordered commitment shares.
    pub fn commitment_shares(&self) -> &[PublicKey] {
        &self.commitment_shares
    }

    /// Return the aggregate commitment.
    pub const fn aggregate_commitment(&self) -> &PublicKey {
        &self.aggregate_commitment
    }

    /// Return the authenticated DOM chain identity carried by the statement.
    pub fn chain_id(&self) -> [u8; 32] {
        self.bytes[6..38]
            .try_into()
            .expect("validated BP statement always contains a 32-byte chain ID")
    }

    /// Return the authenticated contract session identity.
    pub fn session_id(&self) -> [u8; 32] {
        self.bytes[38..70]
            .try_into()
            .expect("validated BP statement always contains a 32-byte session ID")
    }

    /// Return the exact confidential output value bound by this statement.
    pub const fn value_noms(&self) -> u64 {
        self.value_noms
    }

    /// Return the hash of the exact recovery capsule bytes, or the canonical
    /// no-capsule sentinel.
    pub const fn recovery_binding_hash(&self) -> &[u8; 32] {
        &self.recovery_binding_hash
    }
}

/// Exact 138-byte public first-round share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpRound1ShareV1 {
    bytes: [u8; Self::ENCODED_LEN],
}

impl BpRound1ShareV1 {
    /// Canonical encoded length.
    pub const ENCODED_LEN: usize = 138;

    /// Construct and bind a first-round share to one statement participant.
    pub fn new(
        statement: &BpStatementV1,
        participant_index: u16,
        t_one: PublicKey,
        t_two: PublicKey,
    ) -> Result<Self> {
        let participant_id = statement
            .participant_ids()
            .get(usize::from(participant_index))
            .ok_or(AdaptorError::InvalidContext(
                "Bulletproof round participant index is outside the roster",
            ))?;
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..4].copy_from_slice(ROUND1_MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[6..38].copy_from_slice(&statement.statement_hash());
        bytes[38..70].copy_from_slice(participant_id);
        bytes[70..72].copy_from_slice(&participant_index.to_le_bytes());
        bytes[72..105].copy_from_slice(&t_one.to_compressed_bytes());
        bytes[105..138].copy_from_slice(&t_two.to_compressed_bytes());
        Ok(Self { bytes })
    }

    /// Parse and bind a first-round share to the immutable statement.
    pub fn from_bytes(bytes: &[u8], statement: &BpStatementV1) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("BpRound1ShareV1", bytes)?;
        if &bytes[..4] != ROUND1_MAGIC
            || u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..38] != statement.statement_hash()
        {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 1 header or statement hash mismatch",
            ));
        }
        let index = usize::from(u16::from_le_bytes([bytes[70], bytes[71]]));
        let participant_id = exact_array::<32>("BpRound1ShareV1 participant ID", &bytes[38..70])?;
        if statement.participant_ids().get(index) != Some(&participant_id) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 1 participant binding mismatch",
            ));
        }
        PublicKey::from_compressed_bytes(&bytes[72..105])?;
        PublicKey::from_compressed_bytes(&bytes[105..138])?;
        Ok(Self { bytes })
    }

    /// Serialize exact round bytes.
    pub const fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.bytes
    }

    /// Return the pre-reveal commitment for this exact share.
    pub fn reveal_commitment(&self) -> [u8; 32] {
        let mut input = [0u8; 130];
        input[..32].copy_from_slice(&self.bytes[6..38]);
        input[32..64].copy_from_slice(&self.bytes[38..70]);
        input[64..97].copy_from_slice(&self.bytes[72..105]);
        input[97..130].copy_from_slice(&self.bytes[105..138]);
        *blake2b_256_tagged(ROUND1_COMMIT_TAG_V1, &input).as_bytes()
    }
}

/// Exact 104-byte one-shot second-round scalar share.
///
/// This secret-bearing intermediate deliberately implements no clone, copy,
/// debug, display, equality, ordering, or generic serialization. Its owned
/// bytes are compiler-visibly zeroized on drop.
pub struct BpRound2ShareV1 {
    bytes: Zeroizing<[u8; Self::ENCODED_LEN]>,
}

impl BpRound2ShareV1 {
    /// Canonical encoded length.
    pub const ENCODED_LEN: usize = 104;

    /// Construct and bind a second-round share to one statement participant.
    pub(crate) fn new(
        statement: &BpStatementV1,
        participant_index: u16,
        tau_x: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        if !scalar_bytes_are_canonical(&tau_x, true) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof tau_x share is noncanonical",
            ));
        }
        let participant_id = statement
            .participant_ids()
            .get(usize::from(participant_index))
            .ok_or(AdaptorError::InvalidContext(
                "Bulletproof round participant index is outside the roster",
            ))?;
        let mut bytes = Zeroizing::new([0u8; Self::ENCODED_LEN]);
        bytes[..4].copy_from_slice(ROUND2_MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[6..38].copy_from_slice(&statement.statement_hash());
        bytes[38..70].copy_from_slice(participant_id);
        bytes[70..72].copy_from_slice(&participant_index.to_le_bytes());
        bytes[72..104].copy_from_slice(tau_x.as_ref());
        Ok(Self { bytes })
    }

    /// Parse and bind a second-round share to the immutable statement.
    pub fn from_bytes(bytes: &[u8], statement: &BpStatementV1) -> Result<Self> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(AdaptorError::InvalidLength {
                object: "BpRound2ShareV1",
                expected: Self::ENCODED_LEN,
                actual: bytes.len(),
            });
        }
        let mut owned = Zeroizing::new([0u8; Self::ENCODED_LEN]);
        owned.copy_from_slice(bytes);
        let bytes = &owned;
        if &bytes[..4] != ROUND2_MAGIC
            || u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..38] != statement.statement_hash()
        {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 2 header or statement hash mismatch",
            ));
        }
        let index = usize::from(u16::from_le_bytes([bytes[70], bytes[71]]));
        let participant_id = exact_array::<32>("BpRound2ShareV1 participant ID", &bytes[38..70])?;
        if statement.participant_ids().get(index) != Some(&participant_id) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 2 participant binding mismatch",
            ));
        }
        let tau_x = exact_array::<32>("BpRound2ShareV1 tau_x", &bytes[72..104])?;
        if !scalar_bytes_are_canonical(&tau_x, true) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof tau_x share is noncanonical",
            ));
        }
        Ok(Self { bytes: owned })
    }

    /// Consume the share into one zeroizing transport buffer.
    pub fn into_zeroizing_bytes(self) -> Zeroizing<[u8; Self::ENCODED_LEN]> {
        self.bytes
    }
}

/// Opaque common nonce after every ordered reveal matched its prior commitment.
///
/// This internal type has no raw accessor and is consumed by the first backend
/// phase. Phase 2 transport integration remains outside this mission.
pub(crate) struct BpCommonNonceV1(Zeroizing<[u8; 32]>);

/// Independently generated participant-private backend nonce.
///
/// It is imported only from the authenticated short-lived BP vault record,
/// has no raw accessor, and is consumed by backend round one.
pub(crate) struct BpPrivateNonceV1(Zeroizing<[u8; 32]>);

/// One participant's unrevealed common-nonce contribution.
///
/// The share is generated internally, has no raw accessor, and is consumed by
/// collective reveal validation. It implements no clone, copy, debug, display,
/// equality, ordering, or generic serialization.
pub(crate) struct BpCommonNonceShareV1 {
    participant_index: u16,
    reveal: Zeroizing<[u8; 32]>,
}

/// One local collaborative-proof blinding share.
///
/// The share is generated internally and consumed by backend round one. It has
/// no raw accessor and implements no clone, copy, debug, display, equality,
/// ordering, or generic serialization.
pub(crate) struct BpLocalBlindingV1(Zeroizing<[u8; 32]>);

impl BpCommonNonceShareV1 {
    pub(crate) fn generate(statement: &BpStatementV1, participant_index: u16) -> Result<Self> {
        if statement
            .participant_ids()
            .get(usize::from(participant_index))
            .is_none()
        {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof common nonce participant index is outside the roster",
            ));
        }
        let mut reveal = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(reveal.as_mut())
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        Ok(Self {
            participant_index,
            reveal,
        })
    }

    pub(crate) fn commitment(&self, statement: &BpStatementV1) -> Result<[u8; 32]> {
        common_nonce_commitment_for_bytes_v1(statement, self.participant_index, &self.reveal)
    }

    /// Rebuild a share from revealed bytes (§5.4 rodada 0A reveal phase).
    ///
    /// After every commitment `c_i` is accepted, each `q_i` is revealed on the
    /// participants' E2E channel; the receiver reconstructs the share from the
    /// revealed bytes, and `derive_common_nonce_v1` fails closed unless the
    /// share still matches the accepted commitment byte for byte.
    pub(crate) fn from_revealed_bytes(
        statement: &BpStatementV1,
        participant_index: u16,
        reveal: Zeroizing<[u8; 32]>,
    ) -> Result<Self> {
        let share = Self {
            participant_index,
            reveal,
        };
        share.commitment(statement)?;
        Ok(share)
    }

    #[cfg(test)]
    fn from_bytes_for_test(
        statement: &BpStatementV1,
        participant_index: u16,
        reveal: [u8; 32],
    ) -> Result<Self> {
        Self::from_revealed_bytes(statement, participant_index, Zeroizing::new(reveal))
    }
}

impl BpLocalBlindingV1 {
    pub(crate) fn generate() -> Result<Self> {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(bytes.as_mut())
                .map_err(|_| AdaptorError::RandomnessFailure)?;
            if scalar_bytes_are_canonical(&bytes, false) {
                return Ok(Self(bytes));
            }
        }
    }

    /// Inject the party's §4.2 blinding share `r_i` as its local BP blind.
    ///
    /// Spec §5.1: each participant supplies `blinds_i = [r_i, -r_i]` — the
    /// same `r_i` whose pure point `R_i = r_i*G` it published and proved in
    /// the §4.2 session layer. This is the unification the pure-`R_i`
    /// statement made possible: the round layer must be driven by that exact
    /// scalar, not an internally generated one, or the proof's blinds no
    /// longer open the statement's shares.
    pub(crate) fn from_signing_share(share: &crate::SigningShareV1) -> Result<Self> {
        let bytes = Zeroizing::new(*share.as_be_bytes());
        if !scalar_bytes_are_canonical(&bytes, false) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof blinding share is noncanonical",
            ));
        }
        Ok(Self(bytes))
    }

    pub(crate) fn commitment_share(&self, value_share: u64) -> Result<PublicKey> {
        let blind = BlindingFactor::from_bytes(*self.0)?;
        let commitment = dom_crypto::pedersen::Commitment::commit(value_share, &blind);
        PublicKey::from_compressed_bytes(commitment.as_bytes()).map_err(Into::into)
    }

    fn into_blinding(self) -> Result<BlindingFactor> {
        BlindingFactor::from_bytes(*self.0).map_err(Into::into)
    }

    #[cfg(test)]
    fn from_bytes_for_test(bytes: [u8; 32]) -> Result<Self> {
        if !scalar_bytes_are_canonical(&bytes, false) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof test blinding share is noncanonical",
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }
}

impl BpPrivateNonceV1 {
    pub(crate) fn from_persisted_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        if !scalar_bytes_are_canonical(&bytes, false) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof private nonce is noncanonical or zero",
            ));
        }
        Ok(Self(bytes))
    }

    #[cfg(test)]
    fn generate_for_internal_test() -> Result<Self> {
        loop {
            let mut nonce = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(nonce.as_mut())
                .map_err(|_| AdaptorError::RandomnessFailure)?;
            if scalar_bytes_are_canonical(&nonce, false) {
                return Ok(Self(nonce));
            }
        }
    }
}

/// One-shot participant state between backend rounds one and two.
pub(crate) struct BpParticipantRound1StateV1 {
    backend: BulletproofMpcRound1State,
    statement_hash: [u8; 32],
    participant_index: u16,
}

/// One-shot participant state accepted only by final proof construction.
pub(crate) struct BpParticipantFinalizeStateV1 {
    backend: BulletproofMpcFinalizeState,
    statement_hash: [u8; 32],
    participant_index: u16,
}

pub(crate) fn common_nonce_commitment_for_bytes_v1(
    statement: &BpStatementV1,
    participant_index: u16,
    reveal: &[u8; 32],
) -> Result<[u8; 32]> {
    let participant = statement
        .participant_ids()
        .get(usize::from(participant_index))
        .ok_or(AdaptorError::InvalidContext(
            "Bulletproof common nonce participant index is outside the roster",
        ))?;
    let mut input = Zeroizing::new([0u8; 96]);
    input[..32].copy_from_slice(&statement.statement_hash());
    input[32..64].copy_from_slice(participant);
    input[64..].copy_from_slice(reveal);
    Ok(*blake2b_256_tagged(COMMON_COMMIT_TAG_V1, input.as_ref()).as_bytes())
}

/// Consume every common-nonce share and derive the joint backend nonce only
/// after all ordered reveals match the accepted commitment vector byte for
/// byte. No share remains owned by the caller after this operation.
pub(crate) fn derive_common_nonce_v1(
    statement: &BpStatementV1,
    accepted_commitments: &[[u8; 32]],
    ordered_shares: Vec<BpCommonNonceShareV1>,
) -> Result<BpCommonNonceV1> {
    let participant_count = statement.participant_ids().len();
    if accepted_commitments.len() != participant_count || ordered_shares.len() != participant_count
    {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof common nonce vectors must match the participant roster",
        ));
    }
    for (index, (accepted, share)) in accepted_commitments.iter().zip(&ordered_shares).enumerate() {
        let expected_index = u16::try_from(index).map_err(|_| {
            AdaptorError::InvalidContext("Bulletproof participant index exceeds u16")
        })?;
        if share.participant_index != expected_index || share.commitment(statement)? != *accepted {
            return Err(AdaptorError::AuthorizationMismatch);
        }
    }

    let joint_capacity =
        33usize
            .checked_add(64usize.checked_mul(participant_count).ok_or(
                AdaptorError::InvalidContext("Bulletproof joint nonce input length overflow"),
            )?)
            .ok_or(AdaptorError::InvalidContext(
                "Bulletproof joint nonce input length overflow",
            ))?;
    let mut joint_input = Zeroizing::new(Vec::with_capacity(joint_capacity));
    joint_input.extend_from_slice(&statement.statement_hash());
    joint_input.push(
        u8::try_from(participant_count).map_err(|_| {
            AdaptorError::InvalidContext("Bulletproof participant count exceeds u8")
        })?,
    );
    for (participant, share) in statement.participant_ids().iter().zip(&ordered_shares) {
        joint_input.extend_from_slice(participant);
        joint_input.extend_from_slice(share.reveal.as_ref());
    }
    let mut joint_hash = blake2b_256_tagged(COMMON_JOINT_TAG_V1, joint_input.as_ref());
    let joint = Zeroizing::new(*joint_hash.as_bytes());
    joint_hash.zeroize();

    let mut counter = 0u32;
    loop {
        let mut input = Zeroizing::new([0u8; 69]);
        input[1..33].copy_from_slice(&statement.statement_hash());
        input[33..65].copy_from_slice(joint.as_ref());
        input[65..].copy_from_slice(&counter.to_le_bytes());
        let mut first = blake2b_256_tagged(COMMON_NONCE_TAG_V1, input.as_ref());
        input[0] = 1;
        let mut second = blake2b_256_tagged(COMMON_NONCE_TAG_V1, input.as_ref());
        let mut wide = Zeroizing::new([0u8; 64]);
        wide[..32].copy_from_slice(first.as_bytes());
        wide[32..].copy_from_slice(second.as_bytes());
        first.zeroize();
        second.zeroize();
        if let Some(nonce) = scalar_from_wide_be(&wide) {
            return Ok(BpCommonNonceV1(nonce));
        }
        counter = counter
            .checked_add(1)
            .ok_or(AdaptorError::ChallengeCounterOverflow)?;
    }
}

/// Execute a participant's first backend phase and return only its typed public
/// round-one share plus one non-cloneable continuation state.
pub(crate) fn participant_round1_v1(
    statement: &BpStatementV1,
    participant_index: u16,
    local_blinding: BpLocalBlindingV1,
    common_nonce: BpCommonNonceV1,
    private_nonce: BpPrivateNonceV1,
    // Spec §5.2: the proof binds the exact bytes passed as extra_commit — the
    // raw recovery capsule (or empty when the output carries no capsule) — and
    // the statement's recovery_binding_hash is their hash. Consensus verifies
    // the shared output with the same raw bytes (dom-consensus transaction.rs),
    // so the proof must be bound to them, not to the 32-byte hash.
    extra_commit: &[u8],
) -> Result<(BpParticipantRound1StateV1, BpRound1ShareV1)> {
    if statement
        .participant_ids()
        .get(usize::from(participant_index))
        .is_none()
    {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof participant index is outside the roster",
        ));
    }
    let (backend, output) = bulletproof_mpc_round1(
        statement.value_noms(),
        local_blinding.into_blinding()?,
        statement.aggregate_commitment().to_compressed_bytes(),
        common_nonce.0,
        private_nonce.0,
        extra_commit,
    )?;
    let t_one = PublicKey::from_compressed_bytes(output.t_one())?;
    let t_two = PublicKey::from_compressed_bytes(output.t_two())?;
    let share = BpRound1ShareV1::new(statement, participant_index, t_one, t_two)?;
    Ok((
        BpParticipantRound1StateV1 {
            backend,
            statement_hash: statement.statement_hash(),
            participant_index,
        },
        share,
    ))
}

pub(crate) fn aggregate_round1_shares_v1(
    statement: &BpStatementV1,
    shares: &[BpRound1ShareV1],
) -> Result<(PublicKey, PublicKey)> {
    if shares.len() != statement.participant_ids().len() {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof round 1 share set is incomplete",
        ));
    }
    let mut t_one = Vec::with_capacity(shares.len());
    let mut t_two = Vec::with_capacity(shares.len());
    for (expected_index, share) in shares.iter().enumerate() {
        let bytes = share.to_bytes();
        let actual_index = usize::from(u16::from_le_bytes([bytes[70], bytes[71]]));
        if actual_index != expected_index {
            return Err(AdaptorError::ParticipantOrder);
        }
        BpRound1ShareV1::from_bytes(&bytes, statement)?;
        t_one.push(PublicKey::from_compressed_bytes(&bytes[72..105])?);
        t_two.push(PublicKey::from_compressed_bytes(&bytes[105..138])?);
    }
    Ok((
        scriptless_add_public_points(&t_one)?,
        scriptless_add_public_points(&t_two)?,
    ))
}

/// Consume a participant's first-round state in the pinned second phase.
pub(crate) fn participant_round2_v1(
    state: BpParticipantRound1StateV1,
    statement: &BpStatementV1,
    aggregate_t_one: &PublicKey,
    aggregate_t_two: &PublicKey,
) -> Result<(BpParticipantFinalizeStateV1, BpRound2ShareV1)> {
    if state.statement_hash != statement.statement_hash() {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let (backend, tau_x) = bulletproof_mpc_round2(
        state.backend,
        &aggregate_t_one.to_compressed_bytes(),
        &aggregate_t_two.to_compressed_bytes(),
    )?;
    let share = BpRound2ShareV1::new(statement, state.participant_index, tau_x)?;
    Ok((
        BpParticipantFinalizeStateV1 {
            backend,
            statement_hash: state.statement_hash,
            participant_index: state.participant_index,
        },
        share,
    ))
}

/// Consume a participant finalizer into the canonical zeroizing vault
/// continuation plaintext. This is never a network or public object codec.
pub(crate) fn participant_finalize_continuation_to_bytes_v1(
    state: BpParticipantFinalizeStateV1,
    statement: &BpStatementV1,
    participant_index: u16,
) -> Result<Zeroizing<Vec<u8>>> {
    if state.statement_hash != statement.statement_hash()
        || state.participant_index != participant_index
    {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    bulletproof_mpc_finalize_continuation_to_bytes_v1(state.backend).map_err(Into::into)
}

/// Rebuild a participant finalizer only from authenticated canonical vault
/// plaintext and exact statement/aggregate-round-1 public inputs.
pub(crate) fn participant_finalize_continuation_from_bytes_v1(
    bytes: Zeroizing<Vec<u8>>,
    statement: &BpStatementV1,
    participant_index: u16,
    aggregate_t_one: &[u8; 33],
    aggregate_t_two: &[u8; 33],
    extra_commit: &[u8],
) -> Result<BpParticipantFinalizeStateV1> {
    if statement
        .participant_ids()
        .get(usize::from(participant_index))
        .is_none()
    {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof finalizer participant index is outside the roster",
        ));
    }
    let backend = bulletproof_mpc_finalize_continuation_from_bytes_v1(
        bytes,
        statement.value_noms(),
        &statement.aggregate_commitment().to_compressed_bytes(),
        &statement.commitment_shares()[usize::from(participant_index)].to_compressed_bytes(),
        aggregate_t_one,
        aggregate_t_two,
        extra_commit,
    )?;
    Ok(BpParticipantFinalizeStateV1 {
        backend,
        statement_hash: statement.statement_hash(),
        participant_index,
    })
}

fn aggregate_round2_shares_v1(
    statement: &BpStatementV1,
    shares: Vec<BpRound2ShareV1>,
) -> Result<Zeroizing<[u8; 32]>> {
    if shares.len() != statement.participant_ids().len() {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof round 2 share set is incomplete",
        ));
    }
    let mut scalars = Vec::with_capacity(shares.len());
    for (expected_index, share) in shares.into_iter().enumerate() {
        let bytes = share.into_zeroizing_bytes();
        let actual_index = usize::from(u16::from_le_bytes([bytes[70], bytes[71]]));
        if actual_index != expected_index {
            return Err(AdaptorError::ParticipantOrder);
        }
        let mut scalar = Zeroizing::new([0u8; 32]);
        scalar.copy_from_slice(&bytes[72..104]);
        if !scalar_bytes_are_canonical(&scalar, true) {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 2 share is noncanonical",
            ));
        }
        scalars.push(scalar);
    }
    bulletproof_mpc_aggregate_tau_x(scalars).map_err(Into::into)
}

/// Consume one finalizer and every ordered scalar share to produce one proof.
pub(crate) fn finalize_participant_v1(
    state: BpParticipantFinalizeStateV1,
    statement: &BpStatementV1,
    shares: Vec<BpRound2ShareV1>,
) -> Result<Vec<u8>> {
    if state.statement_hash != statement.statement_hash() {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let aggregate_tau_x = aggregate_round2_shares_v1(statement, shares)?;
    bulletproof_mpc_finalize(state.backend, aggregate_tau_x).map_err(Into::into)
}

/// The codec's §5.2 no-recovery sentinel: the binding hash a statement
/// carries when the output has no capsule ("se não houver capsule, usa o
/// sentinel definido no codec, não um None ambíguo").
pub(crate) fn no_recovery_sentinel_v1() -> [u8; 32] {
    *blake2b_256_tagged(NO_RECOVERY_TAG_V1, &[]).as_bytes()
}

fn validate_participants(participant_ids: &[[u8; 32]]) -> Result<()> {
    if !(BpStatementV1::MIN_PARTICIPANTS..=BpStatementV1::MAX_PARTICIPANTS)
        .contains(&participant_ids.len())
    {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof participant count must be 2 through 16",
        ));
    }
    if participant_ids
        .iter()
        .any(|participant| participant == &[0u8; 32])
    {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof participant ID must be nonzero",
        ));
    }
    if participant_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AdaptorError::ParticipantOrder);
    }
    Ok(())
}

fn validate_aggregate(shares: &[PublicKey], aggregate: &PublicKey, value_noms: u64) -> Result<()> {
    // §4.3: the frozen aggregate must equal `v*H + Σ R_i` for the pure blinding
    // shares. This rejects both an aggregate that folds the value into a share
    // and a wire value that disagrees with the recorded shares.
    if BpStatementV1::aggregate_commitment_from_shares(shares, value_noms)? != *aggregate {
        return Err(AdaptorError::InvalidContext(
            "Bulletproof aggregate commitment differs from v*H + ordered share sum",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningShareV1;
    use dom_crypto::range_proof_verify_with_extra_commit;

    fn point(value: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes)
            .expect("small scalar")
            .public_key()
            .clone()
    }

    fn statement() -> BpStatementV1 {
        let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        let shares = vec![point(3), point(5)];
        let aggregate =
            BpStatementV1::aggregate_commitment_from_shares(&shares, 42).expect("aggregate");
        BpStatementV1::new(
            &chain,
            [0x22; 32],
            vec![[0x31; 32], [0x32; 32]],
            42,
            shares,
            aggregate,
            None,
        )
        .expect("statement")
    }

    fn trusted_chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_signed_fixture([0x11; 32])
    }

    #[test]
    fn statement_and_round_codecs_are_exact_and_bound() {
        let statement = statement();
        assert_eq!(statement.to_bytes().len(), 317);
        assert_eq!(
            BpStatementV1::from_bytes(statement.to_bytes(), &trusted_chain()).expect("roundtrip"),
            statement
        );
        let round1 = BpRound1ShareV1::new(&statement, 0, point(7), point(9)).expect("round 1");
        assert_eq!(round1.to_bytes().len(), 138);
        assert_ne!(round1.reveal_commitment(), [0u8; 32]);
        assert_eq!(
            BpRound1ShareV1::from_bytes(&round1.to_bytes(), &statement).expect("roundtrip"),
            round1
        );
        let mut tau = [0u8; 32];
        tau[31] = 11;
        let round2 = BpRound2ShareV1::new(&statement, 1, Zeroizing::new(tau)).expect("round 2");
        let round2_bytes = round2.into_zeroizing_bytes();
        assert_eq!(round2_bytes.len(), 104);
        let reparsed =
            BpRound2ShareV1::from_bytes(round2_bytes.as_ref(), &statement).expect("roundtrip");
        assert_eq!(
            reparsed.into_zeroizing_bytes().as_ref(),
            round2_bytes.as_ref()
        );
        for length in 0..BpRound2ShareV1::ENCODED_LEN {
            assert!(BpRound2ShareV1::from_bytes(&round2_bytes[..length], &statement).is_err());
        }
        for index in 0..BpRound2ShareV1::ENCODED_LEN {
            let mut mutated = Zeroizing::new(*round2_bytes);
            mutated[index] ^= 1;
            if let Ok(parsed) = BpRound2ShareV1::from_bytes(mutated.as_ref(), &statement) {
                assert_ne!(
                    parsed.into_zeroizing_bytes().as_ref(),
                    round2_bytes.as_ref(),
                    "a successful mutation parse must preserve the changed byte"
                );
            }
        }
    }

    #[test]
    fn statement_rejects_reorder_mutation_and_wrong_generator() {
        let statement = statement();
        let mut bytes = statement.to_bytes().to_vec();
        bytes[71..103].fill(0x33);
        assert!(BpStatementV1::from_bytes(&bytes, &trusted_chain()).is_err());

        let count = usize::from(bytes[70]);
        let generator_offset = 71 + 32 * count + 16;
        let mut bytes = statement.to_bytes().to_vec();
        bytes[generator_offset] ^= 1;
        assert!(BpStatementV1::from_bytes(&bytes, &trusted_chain()).is_err());

        let mut bytes = statement.to_bytes().to_vec();
        bytes.push(0);
        assert!(BpStatementV1::from_bytes(&bytes, &trusted_chain()).is_err());
    }

    #[test]
    fn maximum_value_registry_matches_dom_authority() {
        assert_eq!(MAX_PROVABLE_VALUE, (1u64 << 52) - 1);
        let _ = BlindingFactor::from_bytes([0x11; 32]).expect("canonical blind");
    }

    fn collaborative_proof(participant_count: usize) -> Vec<u8> {
        let value = 42u64;
        let mut blinds = Vec::with_capacity(participant_count);
        let mut commitment_shares = Vec::with_capacity(participant_count);
        for index in 0..participant_count {
            let mut bytes = [0u8; 32];
            bytes[31] = u8::try_from(index + 1).expect("at most sixteen participants");
            let blind = BpLocalBlindingV1::from_bytes_for_test(bytes).expect("small nonzero blind");
            // §4.2: each published share is the pure point R_i = r_i*G; the value
            // is carried once by the §4.3 aggregate, not folded into a share.
            commitment_shares.push(
                blind
                    .commitment_share(0)
                    .expect("canonical commitment share"),
            );
            blinds.push(blind);
        }
        let aggregate = BpStatementV1::aggregate_commitment_from_shares(&commitment_shares, value)
            .expect("nonidentity aggregate commitment");
        let statement = BpStatementV1::new(
            &trusted_chain(),
            [0x22; 32],
            (0..participant_count)
                .map(|index| [u8::try_from(index + 1).expect("bounded participant"); 32])
                .collect(),
            value,
            commitment_shares,
            aggregate,
            None,
        )
        .expect("canonical collaborative statement");

        let common_shares = |statement: &BpStatementV1| {
            (0..participant_count)
                .map(|index| {
                    BpCommonNonceShareV1::from_bytes_for_test(
                        statement,
                        u16::try_from(index).expect("bounded participant"),
                        [0x40 + u8::try_from(index).expect("bounded participant"); 32],
                    )
                    .expect("test-only common nonce share")
                })
                .collect::<Vec<_>>()
        };
        let commitments: Vec<[u8; 32]> = common_shares(&statement)
            .iter()
            .map(|share| {
                share
                    .commitment(&statement)
                    .expect("common nonce commitment")
            })
            .collect();

        // Spec §5.2: the proof binds the exact bytes passed as extra_commit,
        // which consensus verifies against — the raw recovery capsule (96 bytes
        // for a capsule-carrying shared output). Bind and verify with the same
        // bytes so this exercises the exact consensus range-proof check shape.
        let extra_commit = [0x5Au8; RECOVERY_CAPSULE_SIZE_BYTES];

        let mut round1_states = Vec::with_capacity(participant_count);
        let mut round1_shares = Vec::with_capacity(participant_count);
        for (index, blind) in blinds.into_iter().enumerate() {
            let common_nonce =
                derive_common_nonce_v1(&statement, &commitments, common_shares(&statement))
                    .expect("verified common nonce");
            let (state, share) = participant_round1_v1(
                &statement,
                u16::try_from(index).expect("bounded participant"),
                blind,
                common_nonce,
                BpPrivateNonceV1::generate_for_internal_test().expect("independent private nonce"),
                &extra_commit,
            )
            .expect("pinned backend round 1");
            round1_states.push(state);
            round1_shares.push(share);
        }
        let (aggregate_t_one, aggregate_t_two) =
            aggregate_round1_shares_v1(&statement, &round1_shares)
                .expect("ordered round 1 aggregation");

        let mut finalizers = Vec::with_capacity(participant_count);
        let mut round2_shares = Vec::with_capacity(participant_count);
        for state in round1_states {
            let (finalizer, share) =
                participant_round2_v1(state, &statement, &aggregate_t_one, &aggregate_t_two)
                    .expect("pinned backend round 2");
            finalizers.push(finalizer);
            round2_shares.push(share);
        }
        let proof = finalize_participant_v1(finalizers.remove(0), &statement, round2_shares)
            .expect("pinned backend finalization");
        // Verify with the exact bytes bound above: this is the same call shape
        // consensus uses for a capsule-carrying output (range_proof_verify_
        // with_extra_commit(commitment, proof, capsule.as_bytes())).
        assert!(range_proof_verify_with_extra_commit(
            &statement.aggregate_commitment().to_compressed_bytes(),
            &proof,
            &extra_commit,
        )
        .expect("unchanged DOM verifier"));
        proof
    }

    /// The recovery-capsule size the shared output carries on the wire.
    const RECOVERY_CAPSULE_SIZE_BYTES: usize = 96;

    #[test]
    fn production_phase_wrapper_handles_two_three_and_sixteen_participants() {
        for participant_count in [2usize, 3, 16] {
            assert_eq!(collaborative_proof(participant_count).len(), 739);
        }
    }
}
