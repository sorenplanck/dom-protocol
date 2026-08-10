//! Public per-participant driver for the collaborative DOM Bulletproof
//! (spec §5.4 "Rodadas" and §5.5 "API segura do wrapper").
//!
//! This is the round layer of the shared-output driver — the half that was
//! gated by §5 until G0 and unblocked by the coordinator's recorded G0
//! revocation. The session layer (§4.2/§4.3) is `collaborative_output.rs`;
//! this module drives the §5.4 rounds over the ratified one-shot backend
//! phases in `bulletproof_mpc.rs`, with the §5.5 API shape:
//!
//! - `CollaborativeRangeProof` — the trait, method for method as §5.5 writes
//!   it (`round1`, `round2`, `finalize`, `verify_final`), with the crate's
//!   `AdaptorError` playing §5.5's `BpError`.
//! - `RangeProof739` — the exact-length proof newtype with `TryFrom<&[u8]>`.
//! - `LocalBpSecrets` — no clone, copy, debug, display, equality, ordering,
//!   or generic serialization. §5.5: "Após produzir o último share, o private
//!   nonce é marcado Consumed antes da mensagem deixar o processo" — every
//!   stage here is take-once: the material moves forward or the call fails
//!   closed with a consumed error, and the round-2 share is only returned
//!   after the local state is already marked consumed.
//!
//! Blinding injection (§5.1 × §4.2): each participant supplies
//! `blinds_i = [r_i, -r_i]` where `r_i` is the same §4.2 blinding share whose
//! pure point `R_i = r_i*G` it published and proved in the session layer.
//! `LocalBpSecrets` fails closed unless the injected share opens the exact
//! `commitment_shares[i]` of the frozen statement — the unification the
//! pure-`R_i` statement exists for.
//!
//! Round mapping (§5.4):
//!
//! - **Rodada 0A** — common-nonce coin toss: `PendingCommonNonce` generates
//!   `q_i`, publishes only the commitment `c_i`; `finish` accepts the reveals
//!   only together with the complete accepted-commitment vector, and
//!   divergence, misorder, or equivocation retires the material (fails
//!   closed). Transporting the ciphertexts on the participants' E2E channel
//!   is the Phase 3 transport's job, not this module's.
//! - **Rodada 0B** — round-1 share commitments: `round1` returns the share,
//!   whose pre-reveal commitment `h_i` (`BpRound1ShareV1::reveal_commitment`)
//!   is published first; `AggregateBpRound1::new` refuses any share whose
//!   commitment does not match the accepted vector, closing the adaptive-
//!   choice channel. NOTE (registry §3.4): the frozen pre-existing code binds
//!   this commitment under `DOM:scriptless-bp-round1-commit:v1` with the
//!   statement hash, while §5.4 writes it under the registered
//!   `DOM:scriptless-nonce-commit:v1` with purpose `"bp-r1"`. The existing
//!   binding is strictly stronger (the statement hash covers the session id
//!   and the whole frozen transcript) and is retained; the tag-name
//!   divergence is recorded for the §3.4 freeze adjudication rather than
//!   silently rewriting frozen evidence.
//! - **Rodada 1** — `T1 = Σ T1_i`, `T2 = Σ T2_i` after commitment, canonical
//!   point, and order checks (`AggregateBpRound1`).
//! - **Rodada 2** — `tau_x_i` over the same statement bytes, common nonce,
//!   private nonce, and aggregated `T1`/`T2`; canonical-scalar checked and
//!   aggregated at finalize (`tau_x = Σ tau_x_i`).
//! - **Rodada 3** — any party finalizes; the §5.4 exit checks are all
//!   enforced: backend success, exactly 739 bytes, the existing
//!   `verify_with_extra_commit` returning success, and the commitment being
//!   the statement's agreed aggregate (the verification runs against it).
//!   On-chain envelope serialization is node-side.
//!
//! §5.2 binding: the statement's `recovery_binding_hash` is the hash of the
//! exact bytes passed as `extra_commit` — the raw recovery/decoy capsule for
//! a capsule-carrying output, or the codec's no-recovery sentinel when the
//! output carries none. The digest framing (plain BLAKE2b-256 over the raw
//! bytes) is PROPOSTO like every Scriptless domain until the §3.4 freeze.

use crate::bulletproof_mpc::{
    aggregate_round1_shares_v1, common_nonce_commitment_for_bytes_v1, derive_common_nonce_v1,
    finalize_participant_v1, no_recovery_sentinel_v1, participant_round1_v1, participant_round2_v1,
    BpCommonNonceShareV1, BpCommonNonceV1, BpLocalBlindingV1, BpParticipantFinalizeStateV1,
    BpParticipantRound1StateV1, BpRound1ShareV1, BpRound2ShareV1, BpStatementV1,
};
use crate::{AdaptorError, Result, SigningShareV1};
use dom_crypto::{blake2b_256, range_proof_verify_with_extra_commit, PublicKey, RANGE_PROOF_SIZE};
use rand_core::{OsRng, RngCore};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Exactly the §5.5 proof container: 739 bytes or nothing.
pub struct RangeProof739([u8; RANGE_PROOF_SIZE]);

impl RangeProof739 {
    /// Borrow the exact proof bytes.
    pub const fn as_bytes(&self) -> &[u8; RANGE_PROOF_SIZE] {
        &self.0
    }
}

impl TryFrom<&[u8]> for RangeProof739 {
    type Error = AdaptorError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| {
            AdaptorError::InvalidLength {
                object: "RangeProof739",
                expected: RANGE_PROOF_SIZE,
                actual: bytes.len(),
            }
        })?))
    }
}

fn consumed() -> AdaptorError {
    AdaptorError::InvalidContext(
        "collaborative range-proof material was already consumed (one-shot)",
    )
}

fn poisoned() -> AdaptorError {
    AdaptorError::InvalidContext("collaborative range-proof state lock is poisoned")
}

/// Rodada 0A commit-phase holder: `q_i` generated, only `c_i` published.
///
/// §5.4: "Todos trocam c_i; só depois trocam q_i pelo canal E2E e conferem os
/// commitments." This type owns the local `q_i` and the injected §4.2
/// blinding until every commitment is accepted; `finish` consumes it. It
/// implements no clone, copy, debug, display, equality, ordering, or generic
/// serialization.
pub struct PendingCommonNonce {
    participant_index: u16,
    statement_hash: [u8; 32],
    blinding: BpLocalBlindingV1,
    own_reveal: Zeroizing<[u8; 32]>,
}

impl PendingCommonNonce {
    /// Begin rodada 0A for one participant, injecting its §4.2 share.
    ///
    /// Fails closed unless `blinding_share` opens the statement's exact
    /// `commitment_shares[participant_index]` — i.e. unless the injected
    /// `r_i` is the very scalar whose `R_i` this participant proved in the
    /// session layer (§4.2/§5.1 unification). Returns the holder and the
    /// commitment `c_i` to publish; `q_i` never leaves the process here.
    pub fn new(
        statement: &BpStatementV1,
        participant_index: u16,
        blinding_share: &SigningShareV1,
    ) -> Result<(Self, [u8; 32])> {
        let expected_share = statement
            .commitment_shares()
            .get(usize::from(participant_index))
            .ok_or(AdaptorError::InvalidContext(
                "collaborative proof participant index is outside the statement",
            ))?;
        if blinding_share.public_key() != expected_share {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let blinding = BpLocalBlindingV1::from_signing_share(blinding_share)?;

        let mut own_reveal = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(own_reveal.as_mut())
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        let commitment =
            common_nonce_commitment_for_bytes_v1(statement, participant_index, &own_reveal)?;
        Ok((
            Self {
                participant_index,
                statement_hash: statement.statement_hash(),
                blinding,
                own_reveal,
            },
            commitment,
        ))
    }

    /// Complete rodada 0A: accept every reveal against the full accepted
    /// commitment vector and derive the joint secrets.
    ///
    /// `accepted_commitments` and `all_reveals` are ordered by participant
    /// index and must cover the whole roster — the API cannot express a
    /// reveal accepted before all commitments (§5.4). A reveal that fails its
    /// accepted commitment, a misindexed entry, or a transcript that lies
    /// about this participant's own contribution retires the material by
    /// consuming `self` and failing closed.
    pub fn finish(
        self,
        statement: &BpStatementV1,
        accepted_commitments: &[[u8; 32]],
        all_reveals: Vec<Zeroizing<[u8; 32]>>,
    ) -> Result<LocalBpSecrets> {
        if self.statement_hash != statement.statement_hash() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let own = all_reveals
            .get(usize::from(self.participant_index))
            .ok_or(AdaptorError::InvalidContext(
                "collaborative proof reveal vector misses this participant",
            ))?;
        if own.as_ref() != self.own_reveal.as_ref() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let mut shares = Vec::with_capacity(all_reveals.len());
        for (index, reveal) in all_reveals.into_iter().enumerate() {
            let index = u16::try_from(index).map_err(|_| {
                AdaptorError::InvalidContext("collaborative proof participant index exceeds u16")
            })?;
            shares.push(BpCommonNonceShareV1::from_revealed_bytes(
                statement, index, reveal,
            )?);
        }
        let common_nonce = derive_common_nonce_v1(statement, accepted_commitments, shares)?;
        Ok(LocalBpSecrets {
            participant_index: self.participant_index,
            statement_hash: self.statement_hash,
            stage: Mutex::new(LocalStage::Ready {
                blinding: self.blinding,
                common_nonce,
            }),
        })
    }
}

enum LocalStage {
    Ready {
        blinding: BpLocalBlindingV1,
        common_nonce: BpCommonNonceV1,
    },
    Round1Done {
        state: BpParticipantRound1StateV1,
    },
    Consumed,
}

/// §5.5 `LocalBpSecrets`: one participant's one-shot round material.
///
/// No clone, copy, debug, display, equality, ordering, or generic
/// serialization. Every stage is take-once behind a lock: the §5.4 rounds
/// each consume the previous stage, and after the round-2 share is produced
/// the state is already `Consumed` before that share can leave the process.
pub struct LocalBpSecrets {
    participant_index: u16,
    statement_hash: [u8; 32],
    stage: Mutex<LocalStage>,
}

/// Rodada 1 aggregate: `T1 = Σ T1_i`, `T2 = Σ T2_i`, accepted only through
/// the rodada 0B commitment gate.
pub struct AggregateBpRound1 {
    statement_hash: [u8; 32],
    t_one: PublicKey,
    t_two: PublicKey,
}

impl AggregateBpRound1 {
    /// Verify every revealed round-1 share against its accepted 0B
    /// commitment, then aggregate.
    ///
    /// §5.4 rodada 0B/1: shares are revealed only after every `h_i` is
    /// accepted; each reveal must reproduce its exact commitment, points must
    /// be canonical, and the order is the roster order. Any mismatch fails
    /// closed with nothing aggregated.
    pub fn new(
        statement: &BpStatementV1,
        accepted_commitments: &[[u8; 32]],
        shares: &[BpRound1ShareV1],
    ) -> Result<Self> {
        if accepted_commitments.len() != shares.len() {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 1 commitment vector must match the share set",
            ));
        }
        for (accepted, share) in accepted_commitments.iter().zip(shares) {
            if share.reveal_commitment() != *accepted {
                return Err(AdaptorError::AuthorizationMismatch);
            }
        }
        let (t_one, t_two) = aggregate_round1_shares_v1(statement, shares)?;
        Ok(Self {
            statement_hash: statement.statement_hash(),
            t_one,
            t_two,
        })
    }
}

/// Rodada 2 aggregate: the ordered `tau_x_i` shares, consumed exactly once by
/// finalization (`tau_x = Σ tau_x_i` happens inside the take).
pub struct AggregateBpRound2 {
    statement_hash: [u8; 32],
    shares: Mutex<Option<Vec<BpRound2ShareV1>>>,
}

impl AggregateBpRound2 {
    /// Collect the ordered round-2 shares for one finalization.
    pub fn new(statement: &BpStatementV1, shares: Vec<BpRound2ShareV1>) -> Result<Self> {
        if shares.len() != statement.participant_ids().len() {
            return Err(AdaptorError::InvalidContext(
                "Bulletproof round 2 share set is incomplete",
            ));
        }
        Ok(Self {
            statement_hash: statement.statement_hash(),
            shares: Mutex::new(Some(shares)),
        })
    }
}

/// §5.5 `CollaborativeRangeProof`, method for method, with `AdaptorError` as
/// the error type (§5.5's `BpError`).
pub trait CollaborativeRangeProof {
    /// Rodada 1 (§5.4): produce this participant's `T1_i`/`T2_i` share.
    fn round1(&self, statement: &BpStatementV1, local: &LocalBpSecrets)
        -> Result<BpRound1ShareV1>;

    /// Rodada 2 (§5.4): produce this participant's `tau_x_i` share against
    /// the aggregated `T1`/`T2`. The local state is marked consumed before
    /// the share is returned.
    fn round2(
        &self,
        statement: &BpStatementV1,
        local: &LocalBpSecrets,
        aggregate_r1: &AggregateBpRound1,
    ) -> Result<BpRound2ShareV1>;

    /// Rodada 3 (§5.4): any party finalizes from the aggregates. Enforces
    /// backend success, the exact 739-byte length, and the consensus-shaped
    /// verification against the statement's agreed commitment.
    fn finalize(
        &self,
        statement: &BpStatementV1,
        aggregate_r1: &AggregateBpRound1,
        aggregate_r2: &AggregateBpRound2,
    ) -> Result<RangeProof739>;

    /// The §5.4 exit check, callable on its own: the existing DOM verifier,
    /// with the exact `extra_commit` bytes, against the agreed commitment.
    fn verify_final(&self, statement: &BpStatementV1, proof: &RangeProof739) -> Result<()>;
}

/// The DOM driver: one instance per participant, bound to one statement and
/// to the exact `extra_commit` bytes the proof and consensus share (§5.2).
pub struct DomCollaborativeRangeProofV1 {
    statement_hash: [u8; 32],
    extra_commit: Vec<u8>,
    finalizer: Mutex<Option<BpParticipantFinalizeStateV1>>,
}

impl DomCollaborativeRangeProofV1 {
    /// Bind a driver to the statement and the raw `extra_commit` bytes.
    ///
    /// §5.2: "recovery_binding_hash é o hash dos bytes exatos passados como
    /// extra_commit; se não houver capsule, usa o sentinel definido no
    /// codec". A capsule-carrying output passes the raw capsule bytes and
    /// their digest must equal the statement's binding hash; an output with
    /// no capsule passes empty bytes and the statement must carry the codec's
    /// no-recovery sentinel. Either mismatch fails closed here, before any
    /// round runs bound to the wrong transcript (§1.3 requires the same
    /// `extra_commit` as the single-party path).
    pub fn new(statement: &BpStatementV1, extra_commit: Vec<u8>) -> Result<Self> {
        let expected = if extra_commit.is_empty() {
            no_recovery_sentinel_v1()
        } else {
            *blake2b_256(&extra_commit).as_bytes()
        };
        if statement.recovery_binding_hash() != &expected {
            return Err(AdaptorError::InvalidContext(
                "extra_commit bytes do not match the statement's recovery binding hash",
            ));
        }
        Ok(Self {
            statement_hash: statement.statement_hash(),
            extra_commit,
            finalizer: Mutex::new(None),
        })
    }

    fn require_statement(&self, statement: &BpStatementV1) -> Result<()> {
        if self.statement_hash != statement.statement_hash() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(())
    }
}

impl CollaborativeRangeProof for DomCollaborativeRangeProofV1 {
    fn round1(
        &self,
        statement: &BpStatementV1,
        local: &LocalBpSecrets,
    ) -> Result<BpRound1ShareV1> {
        self.require_statement(statement)?;
        if local.statement_hash != self.statement_hash {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let mut stage = local.stage.lock().map_err(|_| poisoned())?;
        // Take-once without collateral destruction: a duplicate call fails
        // closed, but material it did not consume stays intact — refusing is
        // fail-closed; destroying valid state on a rejected call would let a
        // stray duplicate retire a live session.
        if !matches!(*stage, LocalStage::Ready { .. }) {
            return Err(consumed());
        }
        let LocalStage::Ready {
            blinding,
            common_nonce,
        } = std::mem::replace(&mut *stage, LocalStage::Consumed)
        else {
            unreachable!("stage variant checked under the same lock");
        };
        let (state, share) = participant_round1_v1(
            statement,
            local.participant_index,
            blinding,
            common_nonce,
            &self.extra_commit,
        )?;
        *stage = LocalStage::Round1Done { state };
        Ok(share)
    }

    fn round2(
        &self,
        statement: &BpStatementV1,
        local: &LocalBpSecrets,
        aggregate_r1: &AggregateBpRound1,
    ) -> Result<BpRound2ShareV1> {
        self.require_statement(statement)?;
        if aggregate_r1.statement_hash != self.statement_hash {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let mut stage = local.stage.lock().map_err(|_| poisoned())?;
        if !matches!(*stage, LocalStage::Round1Done { .. }) {
            return Err(consumed());
        }
        let LocalStage::Round1Done { state } =
            std::mem::replace(&mut *stage, LocalStage::Consumed)
        else {
            unreachable!("stage variant checked under the same lock");
        };
        // §5.5: the local state is Consumed before the share leaves; the
        // finalizer moves into the driver so rodada 3 needs no local secrets.
        let (finalizer, share) =
            participant_round2_v1(state, statement, &aggregate_r1.t_one, &aggregate_r1.t_two)?;
        *self.finalizer.lock().map_err(|_| poisoned())? = Some(finalizer);
        Ok(share)
    }

    fn finalize(
        &self,
        statement: &BpStatementV1,
        aggregate_r1: &AggregateBpRound1,
        aggregate_r2: &AggregateBpRound2,
    ) -> Result<RangeProof739> {
        self.require_statement(statement)?;
        if aggregate_r1.statement_hash != self.statement_hash
            || aggregate_r2.statement_hash != self.statement_hash
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let finalizer = self
            .finalizer
            .lock()
            .map_err(|_| poisoned())?
            .take()
            .ok_or_else(consumed)?;
        let shares = aggregate_r2
            .shares
            .lock()
            .map_err(|_| poisoned())?
            .take()
            .ok_or_else(consumed)?;
        // §5.4 rodada 3: backend success, then exactly 739 bytes, then the
        // existing verifier — all mandatory, none skippable.
        let proof_bytes = finalize_participant_v1(finalizer, statement, shares)?;
        let proof = RangeProof739::try_from(proof_bytes.as_slice())?;
        self.verify_final(statement, &proof)?;
        Ok(proof)
    }

    fn verify_final(&self, statement: &BpStatementV1, proof: &RangeProof739) -> Result<()> {
        self.require_statement(statement)?;
        // The exact call consensus makes for this output class, with the
        // exact bytes the proof was bound to (§5.2/§1.3), against the
        // statement's agreed aggregate commitment.
        let accepted = range_proof_verify_with_extra_commit(
            &statement.aggregate_commitment().to_compressed_bytes(),
            proof.as_bytes(),
            &self.extra_commit,
        )?;
        if !accepted {
            return Err(AdaptorError::VerificationFailed(
                "collaborative proof does not verify under the DOM verifier",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustedChainIdV1;
    use dom_core::Hash256;

    const CAPSULE: [u8; 96] = [0x5A; 96];
    const VALUE: u64 = 42;

    fn chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_authenticated_genesis(0x0011_2233, &Hash256::from_bytes([0x11; 32]))
    }

    fn share(byte: u8) -> SigningShareV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        SigningShareV1::from_be_bytes(bytes).expect("small scalar")
    }

    /// Statement over pure §4.2 shares with the §5.2 capsule binding.
    fn statement(r_a: &SigningShareV1, r_b: &SigningShareV1) -> BpStatementV1 {
        let shares = vec![r_a.public_key().clone(), r_b.public_key().clone()];
        let aggregate =
            BpStatementV1::aggregate_commitment_from_shares(&shares, VALUE).expect("aggregate");
        BpStatementV1::new(
            &chain(),
            [0x22; 32],
            vec![[0x31; 32], [0x32; 32]],
            VALUE,
            shares,
            aggregate,
            Some(*blake2b_256(&CAPSULE).as_bytes()),
        )
        .expect("statement")
    }

    #[test]
    fn injected_share_must_open_the_statement_share() {
        let (r_a, r_b) = (share(3), share(5));
        let statement = statement(&r_a, &r_b);
        // The wrong scalar for slot 0 fails closed before any material exists.
        assert!(matches!(
            PendingCommonNonce::new(&statement, 0, &r_b),
            Err(AdaptorError::AuthorizationMismatch)
        ));
        assert!(PendingCommonNonce::new(&statement, 0, &r_a).is_ok());
    }

    #[test]
    fn driver_binding_rejects_wrong_extra_commit_bytes() {
        let (r_a, r_b) = (share(3), share(5));
        let statement = statement(&r_a, &r_b);
        // Wrong capsule bytes, and empty bytes against a capsule-bound
        // statement, both fail before any round can bind the wrong transcript.
        assert!(DomCollaborativeRangeProofV1::new(&statement, vec![0x00; 96]).is_err());
        assert!(DomCollaborativeRangeProofV1::new(&statement, Vec::new()).is_err());
        assert!(DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).is_ok());
    }

    #[test]
    fn round1_aggregate_enforces_the_0b_commitment_gate() {
        let (r_a, r_b) = (share(3), share(5));
        let statement = statement(&r_a, &r_b);
        let share_a =
            BpRound1ShareV1::new(&statement, 0, share(7).public_key().clone(), share(9).public_key().clone())
                .expect("share A");
        let share_b =
            BpRound1ShareV1::new(&statement, 1, share(11).public_key().clone(), share(13).public_key().clone())
                .expect("share B");
        let commitments = [share_a.reveal_commitment(), share_b.reveal_commitment()];
        assert!(AggregateBpRound1::new(
            &statement,
            &commitments,
            &[share_a.clone(), share_b.clone()]
        )
        .is_ok());

        // A tampered accepted commitment refuses the reveal (§5.4 rodada 0B).
        let mut tampered = commitments;
        tampered[1][0] ^= 1;
        assert!(matches!(
            AggregateBpRound1::new(&statement, &tampered, &[share_a, share_b]),
            Err(AdaptorError::AuthorizationMismatch)
        ));
    }

    #[test]
    fn proof_container_rejects_every_other_length() {
        assert!(RangeProof739::try_from([0u8; 738].as_slice()).is_err());
        assert!(RangeProof739::try_from([0u8; 740].as_slice()).is_err());
        assert!(RangeProof739::try_from([0u8; 739].as_slice()).is_ok());
    }

    /// The full §5.4 choreography, two participants, real backend: 0A commit
    /// and reveal, round 1 behind the 0B gate, round 2, finalization by one
    /// party, and the consensus-shaped verification — with each party's §4.2
    /// scalar driving its round.
    #[test]
    fn two_party_driver_produces_a_739_byte_consensus_verifiable_proof() {
        let (r_a, r_b) = (share(3), share(5));
        let statement = statement(&r_a, &r_b);
        let driver_a =
            DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("driver A");
        let driver_b =
            DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("driver B");

        // Rodada 0A: commitments first, reveals only after both are accepted.
        let (pending_a, commit_a) =
            PendingCommonNonce::new(&statement, 0, &r_a).expect("pending A");
        let (pending_b, commit_b) =
            PendingCommonNonce::new(&statement, 1, &r_b).expect("pending B");
        let accepted = [commit_a, commit_b];
        let reveal_a = Zeroizing::new(*pending_a.own_reveal);
        let reveal_b = Zeroizing::new(*pending_b.own_reveal);
        let local_a = pending_a
            .finish(
                &statement,
                &accepted,
                vec![reveal_a.clone(), reveal_b.clone()],
            )
            .expect("local A");
        let local_b = pending_b
            .finish(&statement, &accepted, vec![reveal_a, reveal_b])
            .expect("local B");

        // Rodada 0B + 1: shares behind the commitment gate, then aggregate.
        let round1_a = driver_a.round1(&statement, &local_a).expect("round1 A");
        let round1_b = driver_b.round1(&statement, &local_b).expect("round1 B");
        // One-shot: a second round1 on the same local fails consumed.
        assert!(driver_a.round1(&statement, &local_a).is_err());
        let accepted_r1 = [round1_a.reveal_commitment(), round1_b.reveal_commitment()];
        let aggregate_r1 = AggregateBpRound1::new(
            &statement,
            &accepted_r1,
            &[round1_a.clone(), round1_b.clone()],
        )
        .expect("aggregate round 1");

        // Rodada 2: tau_x shares; B's crosses the wire as exact bytes.
        let round2_a = driver_a
            .round2(&statement, &local_a, &aggregate_r1)
            .expect("round2 A");
        let round2_b = driver_b
            .round2(&statement, &local_b, &aggregate_r1)
            .expect("round2 B");
        let round2_b_bytes = round2_b.into_zeroizing_bytes();
        let round2_b_received =
            BpRound2ShareV1::from_bytes(round2_b_bytes.as_ref(), &statement).expect("B share");

        // Rodada 3: party A finalizes and the §5.4 exit checks all run.
        let aggregate_r2 = AggregateBpRound2::new(&statement, vec![round2_a, round2_b_received])
            .expect("aggregate round 2");
        let proof = driver_a
            .finalize(&statement, &aggregate_r1, &aggregate_r2)
            .expect("finalize");
        assert_eq!(proof.as_bytes().len(), 739);

        // Both parties can run the exit verification independently.
        driver_a
            .verify_final(&statement, &proof)
            .expect("verify A");
        driver_b
            .verify_final(&statement, &proof)
            .expect("verify B");
        // And it is the exact consensus call shape for a capsule output.
        assert!(range_proof_verify_with_extra_commit(
            &statement.aggregate_commitment().to_compressed_bytes(),
            proof.as_bytes(),
            &CAPSULE,
        )
        .expect("DOM verifier"));

        // One-shot finalization: the aggregates and finalizer are consumed.
        assert!(driver_a
            .finalize(&statement, &aggregate_r1, &aggregate_r2)
            .is_err());
    }
}
