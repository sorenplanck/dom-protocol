//! Shared 2-of-2 output formation and collaborative Bulletproof composition.
//!
//! This module composes primitives the pinned DOM Protocol revision already
//! owns. It defines no curve arithmetic, no hash, no proof system, and no
//! verifier of its own, and it opens no FFI boundary: the multi-party
//! Bulletproof rounds are the pinned `dom_crypto::bulletproof_mpc_*` functions,
//! which own the only `unsafe` in this path.
//!
//! # What is formed
//!
//! ```text
//! R_i = r_i · G          each party's published commitment share
//! R   = R_A + R_B        dom_scriptless_primitives::scriptless_add_public_points
//! C   = v · H_DOM + R    the shared output commitment
//! ```
//!
//! `v · H_DOM` is obtained from the pinned Pedersen commitment rather than by
//! multiplying a generator here: `commit(v, k) − k·G` is exactly the value
//! component, for any nonzero `k`, and both terms are pinned operations.
//!
//! No party learns the other's blind, and neither can spend alone: the opening
//! of `C` is `r_A + r_B`, which exists only as the sum of two secrets that
//! never meet.
//!
//! # Proof of possession is required before aggregation
//!
//! Every published share carries a Schnorr proof of knowledge over the pinned
//! [`dom_adaptor::SharePoPStatementV1`], which binds the chain identifier, the
//! session identifier, the participant roster, the role, the participant index,
//! the terms hash and the recovery binding hash. Aggregating a share whose
//! proof has not verified would be exactly the rogue-key exposure that Stage 5
//! recorded as still owed; here it is closed for this formation.
//!
//! # Boundaries
//!
//! Nothing here funds, refunds, claims, broadcasts, bumps a fee, or reaches a
//! chain. There is no executor and no event surface. The roster is exactly two,
//! as NAR-DC-P1-007 §3 ratified; `n > 2` is refused rather than generalised.
//!
//! ```text
//! PRODUCTION = NOT_AUTHORIZED
//! MAINNET = DISABLED
//! REAL_FUNDS = PROHIBITED
//! PHASE2 = NOT_AUTHORIZED
//! ```

use core::fmt;
use std::error::Error;

use zeroize::Zeroizing;

use dom_adaptor::{
    verify_share_knowledge_v1, BpStatementV1, DirectionV1, SharePoPStatementV1, ShareProofV1,
    TrustedChainIdV1,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{PublicKey};
use dom_scriptless_primitives::{scriptless_add_public_points, secret_scalar_public_key};

/// Exactly two parties form a shared output, as NAR-DC-P1-007 §3 ratified.
pub const SHARED_OUTPUT_PARTIES: usize = 2;

/// One party's published contribution to the shared output.
///
/// Every field is public. No secret, and in particular no blind and no nonce,
/// is accepted here.
pub struct SharedOutputContributionV1 {
    /// Stable participant index, enforcing canonical order.
    pub participant_index: u16,
    /// Canonical participant identifier.
    pub participant_id: [u8; 32],
    /// The party's role in the session.
    pub role: DirectionV1,
    /// The published commitment share `R_i = r_i · G`.
    pub commitment_share: PublicKey,
    /// Proof of knowledge of `r_i`, over the pinned statement.
    pub proof: ShareProofV1,
}

/// Everything the shared-output formation is stated over.
pub struct SharedOutputInputsV1<'a> {
    /// The trusted chain identifier.
    pub chain_id: TrustedChainIdV1,
    /// The unique session identifier.
    pub session_id: [u8; 32],
    /// The two contributions, in canonical roster order.
    pub contributions: &'a [SharedOutputContributionV1],
    /// The committed value in noms.
    pub value_noms: u64,
    /// Digest of the agreed contract terms.
    pub terms_hash: [u8; 32],
    /// The exact recovery capsule / extra-commit digest, as NAR-DC-P1-001 §
    /// field 13 requires.
    pub recovery_binding_hash: [u8; 32],
}

/// Why a shared-output formation was refused.
///
/// Every variant is a refusal. There is no variant meaning "accepted".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SharedOutputError {
    /// The roster is not exactly two parties.
    ///
    /// `n > 2` is out of scope for this product and is refused rather than
    /// generalised.
    NonCanonicalRoster,
    /// Participant indexes are not strictly increasing from zero.
    NonCanonicalOrder,
    /// Two contributions carry the same identifier, share, or role.
    DuplicateParticipant,
    /// A commitment share is not a canonical compressed point.
    NonCanonicalShare,
    /// The chain or session identifier is zero.
    ZeroContext,
    /// The pinned proof-of-possession statement refused the inputs.
    StatementRefused,
    /// A proof of possession did not verify against its own statement.
    ///
    /// Named per participant rather than absorbed, so a rogue share is
    /// attributable instead of surfacing later as an opaque aggregate failure.
    ProofRejected,
    /// The value exceeds the pinned maximum provable value.
    ValueOutOfRange,
    /// Point aggregation produced identity or refused a term.
    AggregationRefused,
    /// The operating system could not supply entropy for a private nonce.
    ///
    /// Terminal by design: a degraded or caller-chosen nonce is never the safe
    /// fallback, because reuse across two proofs over one statement leaks the
    /// Bulletproof blinding.
    EntropyUnavailable,
    /// The pinned Bulletproof statement refused the frozen inputs.
    StatementFrozenRefused,
    /// The pinned backend could not complete and reached no verdict.
    BackendRefused,
}

impl fmt::Display for SharedOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonCanonicalRoster => "the roster is not exactly two parties",
            Self::NonCanonicalOrder => "participant indexes are not canonical",
            Self::DuplicateParticipant => "two contributions are not distinct",
            Self::NonCanonicalShare => "a commitment share is not canonical",
            Self::ZeroContext => "the chain or session identifier is zero",
            Self::StatementRefused => "the pinned proof statement refused the inputs",
            Self::ProofRejected => "a proof of possession did not verify",
            Self::ValueOutOfRange => "the value exceeds the provable maximum",
            Self::AggregationRefused => "point aggregation was refused",
            Self::EntropyUnavailable => "the operating system could not supply entropy",
            Self::StatementFrozenRefused => "the pinned Bulletproof statement was refused",
            Self::BackendRefused => "the pinned backend reached no verdict",
        })
    }
}

impl Error for SharedOutputError {}

/// A frozen shared-output session.
///
/// Issued only by [`freeze_shared_output_statement_v1`], and only after every
/// proof of possession has verified. The fields and the constructor are
/// private, and the type implements neither `Clone`, `Copy`, `Debug`,
/// `Default`, nor any serialization.
///
/// It is evidence that the formation was well-formed. It is not authority: it
/// funds nothing, spends nothing, and authorises no broadcast.
pub struct FrozenSharedOutputV1 {
    statement: BpStatementV1,
    aggregate_share_point: [u8; 33],
    aggregate_commitment: [u8; 33],
    value_noms: u64,
}

impl FrozenSharedOutputV1 {
    /// The pinned Bulletproof statement, frozen before round 1.
    ///
    /// Round 1 must be driven with this exact statement. Freezing it before any
    /// share is produced is what stops a party from steering the proof after
    /// seeing the other side's contribution.
    #[must_use]
    pub const fn statement(&self) -> &BpStatementV1 {
        &self.statement
    }

    /// The aggregate commitment share `R = R_A + R_B`.
    #[must_use]
    pub const fn aggregate_share_point(&self) -> &[u8; 33] {
        &self.aggregate_share_point
    }

    /// The shared output commitment `C = v · H_DOM + R`.
    #[must_use]
    pub const fn aggregate_commitment(&self) -> &[u8; 33] {
        &self.aggregate_commitment
    }

    /// The committed value in noms.
    #[must_use]
    pub const fn value_noms(&self) -> u64 {
        self.value_noms
    }
}

/// The pure value component `v · H_DOM`, derived with pinned operations only.
///
/// `commit(v, k) = v·H_DOM + k·G`, so subtracting `k·G` leaves `v·H_DOM` for
/// any nonzero `k`. The witness `k` is a fixed non-secret constant: it cancels
/// exactly and never reaches the result, so it carries no entropy requirement
/// and is not a blind.
fn value_component(value_noms: u64) -> Result<Commitment, SharedOutputError> {
    let mut witness_bytes = [0_u8; 32];
    witness_bytes[31] = 1;
    let witness =
        BlindingFactor::from_bytes(witness_bytes).map_err(|_| SharedOutputError::BackendRefused)?;
    let with_witness = Commitment::commit(value_noms, &witness);
    let witness_point =
        secret_scalar_public_key(&witness_bytes).map_err(|_| SharedOutputError::BackendRefused)?;
    let witness_commitment =
        Commitment::from_compressed_bytes(&witness_point.to_compressed_bytes())
            .map_err(|_| SharedOutputError::BackendRefused)?;
    with_witness
        .sub(&witness_commitment)
        .map_err(|_| SharedOutputError::AggregationRefused)
}

/// Validate every contribution, aggregate, and freeze the statement.
///
/// The order is deliberate: refuse what can be refused without cryptography,
/// verify every proof of possession against its own pinned statement, and only
/// then aggregate. A share is never summed before its proof has verified.
///
/// # Errors
///
/// Returns the specific [`SharedOutputError`] for the first unsatisfied
/// requirement. No path returns a frozen statement without every pinned check
/// having returned a positive verdict.
pub fn freeze_shared_output_statement_v1(
    inputs: &SharedOutputInputsV1<'_>,
) -> Result<FrozenSharedOutputV1, SharedOutputError> {
    if inputs.contributions.len() != SHARED_OUTPUT_PARTIES {
        return Err(SharedOutputError::NonCanonicalRoster);
    }
    if inputs.chain_id.as_bytes() == &[0_u8; 32] || inputs.session_id == [0_u8; 32] {
        return Err(SharedOutputError::ZeroContext);
    }
    if inputs.value_noms > dom_crypto::MAX_PROVABLE_VALUE {
        return Err(SharedOutputError::ValueOutOfRange);
    }

    for (position, contribution) in inputs.contributions.iter().enumerate() {
        let expected = u16::try_from(position).map_err(|_| SharedOutputError::NonCanonicalOrder)?;
        if contribution.participant_index != expected {
            return Err(SharedOutputError::NonCanonicalOrder);
        }
    }
    let first = &inputs.contributions[0];
    let second = &inputs.contributions[1];
    if first.participant_id == second.participant_id
        || first.role == second.role
        || first.commitment_share.to_compressed_bytes()
            == second.commitment_share.to_compressed_bytes()
    {
        return Err(SharedOutputError::DuplicateParticipant);
    }

    let roster: Vec<[u8; 32]> = inputs
        .contributions
        .iter()
        .map(|contribution| contribution.participant_id)
        .collect();

    // Every proof verifies against its own statement before anything is summed.
    for contribution in inputs.contributions {
        let statement = SharePoPStatementV1::new(
            &inputs.chain_id,
            inputs.session_id,
            &roster,
            contribution.role,
            contribution.participant_index,
            contribution.commitment_share.clone(),
            inputs.terms_hash,
            inputs.recovery_binding_hash,
        )
        .map_err(|_| SharedOutputError::StatementRefused)?;
        match verify_share_knowledge_v1(&statement, &contribution.proof) {
            Ok(true) => {}
            Ok(false) => return Err(SharedOutputError::ProofRejected),
            Err(_) => return Err(SharedOutputError::BackendRefused),
        }
    }

    // R = R_A + R_B, through the pinned aggregation.
    let shares: Vec<PublicKey> = inputs
        .contributions
        .iter()
        .map(|contribution| contribution.commitment_share.clone())
        .collect();
    let aggregate_share =
        scriptless_add_public_points(&shares).map_err(|_| SharedOutputError::AggregationRefused)?;

    // C = v·H_DOM + R.
    let share_commitment =
        Commitment::from_compressed_bytes(&aggregate_share.to_compressed_bytes())
            .map_err(|_| SharedOutputError::NonCanonicalShare)?;
    // At v = 0 the value component is the identity, which the pinned point
    // operations refuse by design. C = 0·H_DOM + R is exactly R, so the term is
    // omitted rather than forced through an operation that rejects identity.
    let aggregate_commitment = if inputs.value_noms == 0 {
        share_commitment
    } else {
        value_component(inputs.value_noms)?
            .add(&share_commitment)
            .map_err(|_| SharedOutputError::AggregationRefused)?
    };
    // The Bulletproof statement is frozen here, before any round-1 share
    // exists. Nothing after this point can steer it.
    // The statement's commitment shares must sum to C, not to R.
    //
    // The pinned driver `participant_round1_v1` feeds
    // `statement.aggregate_commitment()` straight into `bulletproof_mpc_round1`,
    // and the pinned `BpLocalBlindingV1::commitment_share(value_share)` returns
    // `commit(value_share, blind)` — every pinned share carries a value
    // component, and the whole value sits on one participant. `validate_aggregate`
    // only asserts `sum(shares) == aggregate`, so it cannot catch a statement
    // built over R; a statement asserting `v` over an aggregate that opens to 0
    // passes it and is still wrong.
    //
    // The value-carrying shares are derivable from public data alone:
    // `C_0 = v·H_DOM + R_0` and `C_i = R_i` for the rest, so no blind is needed
    // here and their ordered sum is exactly C.
    let mut statement_shares = Vec::with_capacity(shares.len());
    for (position, share) in shares.iter().enumerate() {
        if position == 0 && inputs.value_noms != 0 {
            let carried = Commitment::from_compressed_bytes(&share.to_compressed_bytes())
                .map_err(|_| SharedOutputError::NonCanonicalShare)?;
            let with_value = value_component(inputs.value_noms)?
                .add(&carried)
                .map_err(|_| SharedOutputError::AggregationRefused)?;
            statement_shares.push(
                PublicKey::from_compressed_bytes(with_value.as_bytes())
                    .map_err(|_| SharedOutputError::AggregationRefused)?,
            );
        } else {
            statement_shares.push(share.clone());
        }
    }
    let aggregate_point = PublicKey::from_compressed_bytes(aggregate_commitment.as_bytes())
        .map_err(|_| SharedOutputError::AggregationRefused)?;

    let statement = BpStatementV1::new(
        &inputs.chain_id,
        inputs.session_id,
        roster,
        inputs.value_noms,
        statement_shares,
        aggregate_point,
        Some(inputs.recovery_binding_hash),
    )
    .map_err(|_| SharedOutputError::StatementFrozenRefused)?;

    Ok(FrozenSharedOutputV1 {
        statement,
        aggregate_share_point: aggregate_share.to_compressed_bytes(),
        aggregate_commitment: *aggregate_commitment.as_bytes(),
        value_noms: inputs.value_noms,
    })
}

/// A bilateral commit-reveal for the common nonce.
///
/// The common nonce is an input to every party's round 1, so a party that
/// learned the other's contribution first could choose its own to steer the
/// joint value. Commitments are therefore collected in full before any reveal
/// is accepted, and the joint secret is bound to the frozen statement.
///
/// The type holds no secret. Reveals are 32-byte public contributions; the
/// private nonce each party feeds to round 1 never enters this structure.
pub struct CommonNonceRoundV1 {
    statement_hash: [u8; 32],
    commitments: [Option<[u8; 32]>; SHARED_OUTPUT_PARTIES],
    /// Zeroizing: the reveals jointly determine the rewind nonce, so they carry
    /// the same exposure as the nonce itself.
    reveals: Zeroizing<[Option<[u8; 32]>; SHARED_OUTPUT_PARTIES]>,
}

/// Why a common-nonce round refused a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CommonNonceError {
    /// The participant index is outside the two-party roster.
    UnknownParticipant,
    /// A commitment was already recorded for this participant.
    ///
    /// Accepting a second one would be equivocation.
    DuplicateCommitment,
    /// A reveal arrived before every commitment was in.
    RevealBeforeAllCommitments,
    /// A reveal was already recorded for this participant.
    DuplicateReveal,
    /// The reveal does not open the recorded commitment.
    RevealMismatch,
    /// The round is not complete.
    Incomplete,
    /// The pinned backend reached no verdict.
    BackendRefused,
}

impl fmt::Display for CommonNonceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnknownParticipant => "the participant index is outside the roster",
            Self::DuplicateCommitment => "a commitment was already recorded",
            Self::RevealBeforeAllCommitments => "a reveal arrived before every commitment",
            Self::DuplicateReveal => "a reveal was already recorded",
            Self::RevealMismatch => "the reveal does not open the commitment",
            Self::Incomplete => "the round is not complete",
            Self::BackendRefused => "the pinned backend reached no verdict",
        })
    }
}

impl Error for CommonNonceError {}

/// The joint common nonce, derived once every reveal has opened.
///
/// **This is a secret.** The pinned `bulletproof_mpc_round1` feeds it into
/// grin's *rewind* nonce slot (`TAG_BP2_REWIND_NONCE`), so whoever holds it can
/// rewind the published 739-byte proof and recover both the committed value and
/// the total blinding factor `r_A + r_B` — the spending secret of the shared
/// output. The pinned crate treats it accordingly, as `Zeroizing<[u8; 32]>`.
///
/// It is held zeroizing, has private fields, and implements no `Clone`, `Copy`,
/// `Debug`, `Default`, or serialization.
pub struct JointCommonNonceV1 {
    value: Zeroizing<[u8; 32]>,
}

impl JointCommonNonceV1 {
    /// Borrow the joint nonce for the pinned round 1.
    ///
    /// Both parties hold it, which does not make it public: it is the rewind
    /// nonce, and it must not be logged, stored, or transmitted. Callers should
    /// pass it straight into the pinned round and let it drop.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.value
    }
}

impl CommonNonceRoundV1 {
    /// Open a round bound to one frozen statement.
    #[must_use]
    pub fn open(frozen: &FrozenSharedOutputV1) -> Self {
        Self {
            statement_hash: frozen.statement.statement_hash(),
            commitments: [None; SHARED_OUTPUT_PARTIES],
            reveals: Zeroizing::new([None; SHARED_OUTPUT_PARTIES]),
        }
    }

    /// Record one party's commitment.
    ///
    /// # Errors
    ///
    /// Refuses an unknown index and any second commitment for the same party.
    pub fn accept_commitment(
        &mut self,
        participant_index: u16,
        commitment: [u8; 32],
    ) -> Result<(), CommonNonceError> {
        let slot = usize::from(participant_index);
        if slot >= SHARED_OUTPUT_PARTIES {
            return Err(CommonNonceError::UnknownParticipant);
        }
        if self.commitments[slot].is_some() {
            return Err(CommonNonceError::DuplicateCommitment);
        }
        self.commitments[slot] = Some(commitment);
        Ok(())
    }

    /// Record one party's reveal, only after every commitment is in.
    ///
    /// # Errors
    ///
    /// Refuses an early reveal, a duplicate, and a reveal that does not open
    /// the recorded commitment.
    pub fn accept_reveal(
        &mut self,
        participant_index: u16,
        reveal: [u8; 32],
    ) -> Result<(), CommonNonceError> {
        let slot = usize::from(participant_index);
        if slot >= SHARED_OUTPUT_PARTIES {
            return Err(CommonNonceError::UnknownParticipant);
        }
        if self.commitments.iter().any(Option::is_none) {
            return Err(CommonNonceError::RevealBeforeAllCommitments);
        }
        if self.reveals[slot].is_some() {
            return Err(CommonNonceError::DuplicateReveal);
        }
        let recorded = self.commitments[slot].ok_or(CommonNonceError::UnknownParticipant)?;
        if commit_to_reveal(&self.statement_hash, participant_index, &reveal)? != recorded {
            return Err(CommonNonceError::RevealMismatch);
        }
        self.reveals[slot] = Some(reveal);
        Ok(())
    }

    /// Derive the joint common nonce once both reveals have opened.
    ///
    /// # Errors
    ///
    /// Refuses an incomplete round.
    pub fn joint_nonce(&self) -> Result<JointCommonNonceV1, CommonNonceError> {
        let mut body = Vec::with_capacity(32 + 32 * SHARED_OUTPUT_PARTIES);
        body.extend_from_slice(&self.statement_hash);
        for reveal in self.reveals.iter() {
            let value = reveal.ok_or(CommonNonceError::Incomplete)?;
            body.extend_from_slice(&value);
        }
        let digest = dom_crypto::blake2b_256_tagged(COMMON_NONCE_TAG_V1, &body);
        Ok(JointCommonNonceV1 {
            value: Zeroizing::new(*digest.as_bytes()),
        })
    }
}

/// Domain tag for the common-nonce commitment and joint derivation.
const COMMON_NONCE_TAG_V1: &str = "DOM:contracts-shared-output-common-nonce:v1";

/// The canonical commitment to a reveal, bound to statement and participant.
///
/// Binding the participant index stops one party from replaying the other's
/// commitment as its own.
///
/// # Errors
///
/// Returns [`CommonNonceError::BackendRefused`] if the pinned hash refuses.
pub fn commit_to_reveal(
    statement_hash: &[u8; 32],
    participant_index: u16,
    reveal: &[u8; 32],
) -> Result<[u8; 32], CommonNonceError> {
    let mut body = Vec::with_capacity(66);
    body.extend_from_slice(statement_hash);
    body.extend_from_slice(&participant_index.to_le_bytes());
    body.extend_from_slice(reveal);
    let digest = dom_crypto::blake2b_256_tagged(COMMON_NONCE_TAG_V1, &body);
    Ok(*digest.as_bytes())
}

/// One private nonce for the collaborative Bulletproof, held for exactly one use.
///
/// The pinned canonical driver `participant_round1_v1` draws this value from
/// the operating system internally and never lets a caller supply it. That
/// driver is `pub(crate)` and unreachable, so this repository must drive the
/// raw FFI — and with it inherits the custody duty the driver was discharging.
///
/// This type is that duty, expressed where the boundary permits it. It is
/// generated from OS entropy, never from a caller-supplied value; it is
/// consumed **by value** on use, so the same nonce cannot be handed to a second
/// round; and it implements no `Clone`, `Copy`, `Debug`, `Default`, or
/// serialization, so it cannot be duplicated, printed, or stored.
///
/// # What this does not do
///
/// It is not the Vault. `docs/architecture/BOUNDARIES.md` forbids this crate a
/// filesystem, so durable `Consumed` state and the tombstone that must outlive
/// a crash belong to `dom-scriptless-store` under NAR-DC-P1-004 §8 and
/// NAR-DC-P1-005, wired at the composition root. This type makes reuse
/// impossible **within one process**; it cannot make it impossible across a
/// crash, and it does not claim to.
///
/// Why it still matters: a repeated or predictable private nonce across two
/// proofs over the same statement leaks the `tau_1`/`tau_2` blinding. Before
/// this type there was no value in this repository standing between a caller
/// and the raw FFI at all.
pub struct PrivateNonceCustodyV1 {
    value: Zeroizing<[u8; 32]>,
}

impl PrivateNonceCustodyV1 {
    /// Draw one private nonce from the operating system.
    ///
    /// There is deliberately no constructor taking bytes. A caller-chosen
    /// private nonce is the failure this type exists to prevent, so the type
    /// system refuses it rather than a runtime check.
    ///
    /// # Errors
    ///
    /// Returns [`SharedOutputError::EntropyUnavailable`] if the operating
    /// system cannot supply entropy. That is terminal: proceeding with a
    /// degraded nonce is never the safe fallback.
    pub fn draw() -> Result<Self, SharedOutputError> {
        let mut value = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(value.as_mut()).map_err(|_| SharedOutputError::EntropyUnavailable)?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(SharedOutputError::EntropyUnavailable);
        }
        Ok(Self { value })
    }

    /// Consume the custody and yield the nonce for exactly one pinned round.
    ///
    /// Taking `self` by value is the whole point: the custody is gone
    /// afterwards, so a second round cannot be driven with the same nonce.
    #[must_use]
    pub fn into_round_nonce(self) -> Zeroizing<[u8; 32]> {
        self.value
    }
}
