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
    BpParticipantRound1StateV1, BpPrivateNonceV1, BpRound1ShareV1, BpRound2ShareV1, BpStatementV1,
};
use crate::{
    AdaptorError, CollaborativeBpFinalizeBindingV1, CollaborativeBpFinalizeContinuationV1,
    CollaborativeBpFinalizeImportCapabilityV1, CollaborativeBpNonceBindingV1,
    CollaborativeBpNonceImportCapabilityV1, CollaborativeBpNonceMaterialV1,
    CollaborativeBpNonceSealCapabilityV1, CollaborativeBpNonceVaultError,
    CollaborativeBpNonceVaultV1, CollaborativeBpProofImportCapabilityV1,
    CollaborativeBpProofPersistenceCapabilityV1, CollaborativeBpRound2ImportCapabilityV1,
    CollaborativeBpRound2PersistenceCapabilityV1, DurableBpProofTransportV1,
    DurableBpRound2TransportV1, Result, SigningShareV1,
};
use dom_crypto::{blake2b_256, range_proof_verify_with_extra_commit, PublicKey, RANGE_PROOF_SIZE};
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
    private_nonce: BpPrivateNonceV1,
}

impl PendingCommonNonce {
    fn require_bound_share(
        statement: &BpStatementV1,
        participant_index: u16,
        blinding_share: &SigningShareV1,
    ) -> Result<()> {
        let expected_share = statement
            .commitment_shares()
            .get(usize::from(participant_index))
            .ok_or(AdaptorError::InvalidContext(
                "collaborative proof participant index is outside the statement",
            ))?;
        if blinding_share.public_key() != expected_share {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(())
    }

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
        let material = CollaborativeBpNonceMaterialV1::generate_from_os_rng()?;
        Self::from_persisted_material_v1(statement, participant_index, blinding_share, material)
    }

    /// Generate, durably seal, reopen, and validate fresh rodada-0A/backend
    /// nonce material before releasing `c_i`.
    ///
    /// Production F7 callers use this entry instead of [`Self::new`]. The
    /// selected vault sees the plaintext only through a one-shot seal/import
    /// capability, authenticates the complete statement/session binding, and
    /// must fsync the fresh record before returning. No public commitment is
    /// computed until the authenticated reopen succeeds.
    pub fn new_vault_backed_v1<Vault: CollaborativeBpNonceVaultV1>(
        statement: &BpStatementV1,
        participant_index: u16,
        blinding_share: &SigningShareV1,
        vault: &mut Vault,
    ) -> core::result::Result<(Self, [u8; 32]), CollaborativeBpNonceVaultError<Vault::Error>> {
        Self::require_bound_share(statement, participant_index, blinding_share)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let binding = CollaborativeBpNonceBindingV1::from_statement(statement, participant_index)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let material = CollaborativeBpNonceMaterialV1::generate_from_os_rng()
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        vault
            .seal_fresh_material(
                &binding,
                material,
                CollaborativeBpNonceSealCapabilityV1::new(),
            )
            .map_err(CollaborativeBpNonceVaultError::Vault)?;
        Self::resume_vault_backed_v1(statement, participant_index, blinding_share, vault)
    }

    /// Reconstruct the exact pending state from an authenticated encrypted
    /// record after restart.
    ///
    /// The store owns whether its monotonic stage still permits this open. It
    /// must reject consumed, replaced, rolled-back, or differently bound
    /// material. Recomputed public bytes are deterministic for the same record;
    /// once a later public artifact exists, the store retransmits those already
    /// persisted bytes instead of reopening this method.
    pub fn resume_vault_backed_v1<Vault: CollaborativeBpNonceVaultV1>(
        statement: &BpStatementV1,
        participant_index: u16,
        blinding_share: &SigningShareV1,
        vault: &mut Vault,
    ) -> core::result::Result<(Self, [u8; 32]), CollaborativeBpNonceVaultError<Vault::Error>> {
        Self::require_bound_share(statement, participant_index, blinding_share)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let binding = CollaborativeBpNonceBindingV1::from_statement(statement, participant_index)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let material = vault
            .open_persisted_material(&binding, CollaborativeBpNonceImportCapabilityV1::new())
            .map_err(CollaborativeBpNonceVaultError::Vault)?;
        Self::from_persisted_material_v1(statement, participant_index, blinding_share, material)
            .map_err(CollaborativeBpNonceVaultError::Protocol)
    }

    /// Rebuild a pending state from opaque, AEAD-authenticated persisted
    /// material.
    ///
    /// Ordinary callers cannot construct `material`; only the driver's private
    /// import capability can. This method revalidates the statement's exact
    /// participant share, consumes both secret halves, and returns only the
    /// public commitment alongside the one-shot pending state.
    pub fn from_persisted_material_v1(
        statement: &BpStatementV1,
        participant_index: u16,
        blinding_share: &SigningShareV1,
        material: CollaborativeBpNonceMaterialV1,
    ) -> Result<(Self, [u8; 32])> {
        Self::require_bound_share(statement, participant_index, blinding_share)?;
        let blinding = BpLocalBlindingV1::from_signing_share(blinding_share)?;
        let (own_reveal, private_nonce) = material.into_parts();
        let private_nonce = BpPrivateNonceV1::from_persisted_bytes(private_nonce)?;
        let commitment =
            common_nonce_commitment_for_bytes_v1(statement, participant_index, &own_reveal)?;
        Ok((
            Self {
                participant_index,
                statement_hash: statement.statement_hash(),
                blinding,
                own_reveal,
                private_nonce,
            },
            commitment,
        ))
    }

    /// This participant's reveal `q_i`, for the rodada 0A reveal phase.
    ///
    /// §5.4: after every commitment `c_i` is accepted, "revelar q_i somente
    /// no canal E2E entre participantes" — the caller transports these bytes
    /// on the participants' end-to-end channel only, never through a
    /// coordinator that could read them, and never before the full
    /// commitment vector is accepted. The returned copy is caller-zeroized.
    pub fn reveal_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.own_reveal)
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
        let own = all_reveals.get(usize::from(self.participant_index)).ok_or(
            AdaptorError::InvalidContext(
                "collaborative proof reveal vector misses this participant",
            ),
        )?;
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
                private_nonce: self.private_nonce,
            }),
        })
    }
}

enum LocalStage {
    Ready {
        blinding: BpLocalBlindingV1,
        common_nonce: BpCommonNonceV1,
        private_nonce: BpPrivateNonceV1,
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
    fn round1(&self, statement: &BpStatementV1, local: &LocalBpSecrets) -> Result<BpRound1ShareV1>;

    /// Rodada 2 (§5.4): produce this participant's `tau_x_i` share against
    /// the aggregated `T1`/`T2`. The local state is marked consumed before
    /// the share is returned.
    ///
    /// This frozen compatibility surface is for deterministic tests and
    /// non-operational tooling. F7 production composition must call
    /// [`DomCollaborativeRangeProofV1::round2_vault_backed_v1`] so persistence
    /// and the durable nonce tombstone precede transport exposure.
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

    fn produce_round2_parts(
        &self,
        statement: &BpStatementV1,
        local: &LocalBpSecrets,
        aggregate_r1: &AggregateBpRound1,
    ) -> Result<(BpParticipantFinalizeStateV1, BpRound2ShareV1)> {
        self.require_statement(statement)?;
        if aggregate_r1.statement_hash != self.statement_hash {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let mut stage = local.stage.lock().map_err(|_| poisoned())?;
        if !matches!(*stage, LocalStage::Round1Done { .. }) {
            return Err(consumed());
        }
        let LocalStage::Round1Done { state } = std::mem::replace(&mut *stage, LocalStage::Consumed)
        else {
            unreachable!("stage variant checked under the same lock");
        };
        // §5.5: local state is Consumed before either result can leave. The
        // compatibility path keeps the finalizer process-local; the F7 path
        // sends it immediately to the retained vault in the same boundary.
        participant_round2_v1(state, statement, &aggregate_r1.t_one, &aggregate_r1.t_two)
    }

    fn produce_round2_share(
        &self,
        statement: &BpStatementV1,
        local: &LocalBpSecrets,
        aggregate_r1: &AggregateBpRound1,
    ) -> Result<BpRound2ShareV1> {
        let (finalizer, share) = self.produce_round2_parts(statement, local, aggregate_r1)?;
        *self.finalizer.lock().map_err(|_| poisoned())? = Some(finalizer);
        Ok(share)
    }

    fn finalize_binding_v1(
        &self,
        statement: &BpStatementV1,
        participant_index: u16,
        aggregate_r1: &AggregateBpRound1,
    ) -> Result<CollaborativeBpFinalizeBindingV1> {
        self.require_statement(statement)?;
        if aggregate_r1.statement_hash != self.statement_hash {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let nonce_binding =
            CollaborativeBpNonceBindingV1::from_statement(statement, participant_index)?;
        CollaborativeBpFinalizeBindingV1::new(
            &nonce_binding,
            statement,
            aggregate_r1.t_one.to_compressed_bytes(),
            aggregate_r1.t_two.to_compressed_bytes(),
            &self.extra_commit,
        )
    }

    /// Production round-2 boundary: persist the exact encrypted `tau_x_i`
    /// artifact and atomically retire its nonce record before any transport
    /// bytes can leave the driver.
    ///
    /// A vault error returns no share bytes. If the retained transaction
    /// committed before a crash/error became observable, recovery proceeds only
    /// through [`Self::resume_persisted_round2_v1`]; the consumed nonce is never
    /// reopened or recomputed.
    pub fn round2_vault_backed_v1<Vault: CollaborativeBpNonceVaultV1>(
        &self,
        statement: &BpStatementV1,
        local: &LocalBpSecrets,
        aggregate_r1: &AggregateBpRound1,
        vault: &mut Vault,
    ) -> core::result::Result<
        DurableBpRound2TransportV1,
        CollaborativeBpNonceVaultError<Vault::Error>,
    > {
        let (finalizer, share) = self
            .produce_round2_parts(statement, local, aggregate_r1)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let binding = self
            .finalize_binding_v1(statement, local.participant_index, aggregate_r1)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        vault
            .persist_round2_and_consume_material(
                &binding,
                statement,
                CollaborativeBpFinalizeContinuationV1::new(finalizer),
                share,
                CollaborativeBpRound2PersistenceCapabilityV1::new(&binding, statement),
            )
            .map_err(CollaborativeBpNonceVaultError::Vault)
    }

    /// Reopen a one-send byte-identical round-2 authority after restart or ACK
    /// loss, using only the immutable encrypted artifact and its terminal nonce
    /// tombstone.
    pub fn resume_persisted_round2_v1<Vault: CollaborativeBpNonceVaultV1>(
        &self,
        statement: &BpStatementV1,
        participant_index: u16,
        vault: &mut Vault,
    ) -> core::result::Result<
        DurableBpRound2TransportV1,
        CollaborativeBpNonceVaultError<Vault::Error>,
    > {
        self.require_statement(statement)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let binding = CollaborativeBpNonceBindingV1::from_statement(statement, participant_index)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        vault
            .open_persisted_round2(
                &binding,
                statement,
                CollaborativeBpRound2ImportCapabilityV1::for_restart(&binding),
            )
            .map_err(CollaborativeBpNonceVaultError::Vault)
    }

    /// Resume final proof construction after any restart following round 2.
    ///
    /// The Store reopens the encrypted finalizer continuation without opening
    /// the consumed BP nonce record. Only after the unchanged DOM verifier
    /// accepts the exact 739-byte result does the Store atomically persist the
    /// proof and retire the continuation. Thus both pre-proof and post-proof
    /// crash positions have a deterministic retained recovery path.
    pub fn finalize_vault_backed_v1<Vault: CollaborativeBpNonceVaultV1>(
        &self,
        statement: &BpStatementV1,
        participant_index: u16,
        aggregate_r1: &AggregateBpRound1,
        aggregate_r2: &AggregateBpRound2,
        vault: &mut Vault,
    ) -> core::result::Result<DurableBpProofTransportV1, CollaborativeBpNonceVaultError<Vault::Error>>
    {
        if aggregate_r2.statement_hash != self.statement_hash {
            return Err(CollaborativeBpNonceVaultError::Protocol(
                AdaptorError::AuthorizationMismatch,
            ));
        }
        let binding = self
            .finalize_binding_v1(statement, participant_index, aggregate_r1)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let continuation = vault
            .open_persisted_finalize_continuation(
                &binding,
                statement,
                CollaborativeBpFinalizeImportCapabilityV1::for_restart(&binding),
            )
            .map_err(CollaborativeBpNonceVaultError::Vault)?;
        let shares = aggregate_r2
            .shares
            .lock()
            .map_err(|_| CollaborativeBpNonceVaultError::Protocol(poisoned()))?
            .take()
            .ok_or_else(|| CollaborativeBpNonceVaultError::Protocol(consumed()))?;
        let proof_bytes = finalize_participant_v1(continuation.into_state(), statement, shares)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        let proof = RangeProof739::try_from(proof_bytes.as_slice())
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        self.verify_final(statement, &proof)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        vault
            .persist_verified_proof_and_consume_finalize(
                &binding,
                statement,
                proof,
                CollaborativeBpProofPersistenceCapabilityV1::new(&binding, statement),
            )
            .map_err(CollaborativeBpNonceVaultError::Vault)
    }

    /// Reopen an already persisted proof for byte-identical output assembly or
    /// retransmission after restart, without restoring any secret state.
    pub fn resume_persisted_proof_v1<Vault: CollaborativeBpNonceVaultV1>(
        &self,
        statement: &BpStatementV1,
        participant_index: u16,
        aggregate_r1: &AggregateBpRound1,
        vault: &mut Vault,
    ) -> core::result::Result<DurableBpProofTransportV1, CollaborativeBpNonceVaultError<Vault::Error>>
    {
        let binding = self
            .finalize_binding_v1(statement, participant_index, aggregate_r1)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        vault
            .open_persisted_proof(
                &binding,
                statement,
                CollaborativeBpProofImportCapabilityV1::for_restart(&binding),
            )
            .map_err(CollaborativeBpNonceVaultError::Vault)
    }
}

impl CollaborativeRangeProof for DomCollaborativeRangeProofV1 {
    fn round1(&self, statement: &BpStatementV1, local: &LocalBpSecrets) -> Result<BpRound1ShareV1> {
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
            private_nonce,
        } = std::mem::replace(&mut *stage, LocalStage::Consumed)
        else {
            unreachable!("stage variant checked under the same lock");
        };
        let (state, share) = participant_round1_v1(
            statement,
            local.participant_index,
            blinding,
            common_nonce,
            private_nonce,
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
        self.produce_round2_share(statement, local, aggregate_r1)
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
    use crate::{
        CollaborativeBpNonceBindingV1, CollaborativeBpNonceImportCapabilityV1,
        CollaborativeBpNonceMaterialV1, CollaborativeBpNonceSealCapabilityV1,
        CollaborativeBpNonceVaultV1, TrustedChainIdV1,
    };
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

    #[derive(Debug, thiserror::Error)]
    #[error("test collaborative-BP nonce vault failure")]
    struct TestNonceVaultError;

    #[derive(Default)]
    struct TestNonceVault {
        binding: Option<CollaborativeBpNonceBindingV1>,
        plaintext: Option<[u8; 64]>,
        finalize_binding: Option<CollaborativeBpFinalizeBindingV1>,
        finalize_plaintext: Option<Zeroizing<Vec<u8>>>,
        round2_plaintext: Option<[u8; BpRound2ShareV1::ENCODED_LEN]>,
        round2_consumed: bool,
        finalize_consumed: bool,
        proof_plaintext: Option<[u8; dom_crypto::RANGE_PROOF_SIZE]>,
        seal_count: usize,
        open_count: usize,
        round2_persist_count: usize,
        round2_open_count: usize,
        finalize_open_count: usize,
        proof_persist_count: usize,
        proof_open_count: usize,
    }

    impl CollaborativeBpNonceVaultV1 for TestNonceVault {
        type Error = TestNonceVaultError;

        fn seal_fresh_material(
            &mut self,
            binding: &CollaborativeBpNonceBindingV1,
            material: CollaborativeBpNonceMaterialV1,
            capability: CollaborativeBpNonceSealCapabilityV1,
        ) -> core::result::Result<(), Self::Error> {
            if self.binding.is_some() || self.plaintext.is_some() {
                return Err(TestNonceVaultError);
            }
            self.binding = Some(binding.clone());
            self.plaintext = Some(*capability.into_plaintext(material));
            self.seal_count += 1;
            Ok(())
        }

        fn open_persisted_material(
            &mut self,
            binding: &CollaborativeBpNonceBindingV1,
            capability: CollaborativeBpNonceImportCapabilityV1,
        ) -> core::result::Result<CollaborativeBpNonceMaterialV1, Self::Error> {
            if self.binding.as_ref() != Some(binding) {
                return Err(TestNonceVaultError);
            }
            self.open_count += 1;
            capability
                .import(Zeroizing::new(self.plaintext.ok_or(TestNonceVaultError)?))
                .map_err(|_| TestNonceVaultError)
        }

        fn persist_round2_and_consume_material(
            &mut self,
            binding: &CollaborativeBpFinalizeBindingV1,
            statement: &BpStatementV1,
            continuation: CollaborativeBpFinalizeContinuationV1,
            share: BpRound2ShareV1,
            capability: CollaborativeBpRound2PersistenceCapabilityV1,
        ) -> core::result::Result<DurableBpRound2TransportV1, Self::Error> {
            if self.binding.as_ref() != Some(binding.nonce_binding())
                || self.plaintext.is_none()
                || self.round2_plaintext.is_some()
                || self.finalize_plaintext.is_some()
                || self.round2_consumed
            {
                return Err(TestNonceVaultError);
            }
            let (finalize_plaintext, round2_plaintext, finalize_import, round2_import) = capability
                .into_plaintext(continuation, share)
                .map_err(|_| TestNonceVaultError)?;
            self.finalize_binding = Some(binding.clone());
            self.finalize_plaintext = Some(finalize_plaintext);
            self.round2_plaintext = Some(*round2_plaintext);
            self.plaintext = None;
            self.round2_consumed = true;
            self.round2_persist_count += 1;
            let _authenticated_continuation = finalize_import
                .import(
                    statement,
                    Zeroizing::new(
                        self.finalize_plaintext
                            .as_ref()
                            .ok_or(TestNonceVaultError)?
                            .as_slice()
                            .to_vec(),
                    ),
                )
                .map_err(|_| TestNonceVaultError)?;
            round2_import
                .import(
                    statement,
                    Zeroizing::new(self.round2_plaintext.ok_or(TestNonceVaultError)?),
                )
                .map_err(|_| TestNonceVaultError)
        }

        fn open_persisted_round2(
            &mut self,
            binding: &CollaborativeBpNonceBindingV1,
            statement: &BpStatementV1,
            capability: CollaborativeBpRound2ImportCapabilityV1,
        ) -> core::result::Result<DurableBpRound2TransportV1, Self::Error> {
            if self.binding.as_ref() != Some(binding)
                || !self.round2_consumed
                || self.plaintext.is_some()
            {
                return Err(TestNonceVaultError);
            }
            self.round2_open_count += 1;
            capability
                .import(
                    statement,
                    Zeroizing::new(self.round2_plaintext.ok_or(TestNonceVaultError)?),
                )
                .map_err(|_| TestNonceVaultError)
        }

        fn open_persisted_finalize_continuation(
            &mut self,
            binding: &CollaborativeBpFinalizeBindingV1,
            statement: &BpStatementV1,
            capability: CollaborativeBpFinalizeImportCapabilityV1,
        ) -> core::result::Result<CollaborativeBpFinalizeContinuationV1, Self::Error> {
            if self.finalize_binding.as_ref() != Some(binding)
                || !self.round2_consumed
                || self.plaintext.is_some()
                || self.finalize_consumed
            {
                return Err(TestNonceVaultError);
            }
            self.finalize_open_count += 1;
            capability
                .import(
                    statement,
                    Zeroizing::new(
                        self.finalize_plaintext
                            .as_ref()
                            .ok_or(TestNonceVaultError)?
                            .as_slice()
                            .to_vec(),
                    ),
                )
                .map_err(|_| TestNonceVaultError)
        }

        fn persist_verified_proof_and_consume_finalize(
            &mut self,
            binding: &CollaborativeBpFinalizeBindingV1,
            statement: &BpStatementV1,
            proof: RangeProof739,
            capability: CollaborativeBpProofPersistenceCapabilityV1,
        ) -> core::result::Result<DurableBpProofTransportV1, Self::Error> {
            if self.finalize_binding.as_ref() != Some(binding)
                || self.finalize_plaintext.is_none()
                || self.finalize_consumed
                || self.proof_plaintext.is_some()
            {
                return Err(TestNonceVaultError);
            }
            let (plaintext, import) = capability
                .into_plaintext(proof)
                .map_err(|_| TestNonceVaultError)?;
            self.proof_plaintext = Some(plaintext);
            self.finalize_plaintext = None;
            self.finalize_consumed = true;
            self.proof_persist_count += 1;
            import
                .import(statement, self.proof_plaintext.ok_or(TestNonceVaultError)?)
                .map_err(|_| TestNonceVaultError)
        }

        fn open_persisted_proof(
            &mut self,
            binding: &CollaborativeBpFinalizeBindingV1,
            statement: &BpStatementV1,
            capability: CollaborativeBpProofImportCapabilityV1,
        ) -> core::result::Result<DurableBpProofTransportV1, Self::Error> {
            if self.finalize_binding.as_ref() != Some(binding)
                || !self.finalize_consumed
                || self.finalize_plaintext.is_some()
            {
                return Err(TestNonceVaultError);
            }
            self.proof_open_count += 1;
            capability
                .import(statement, self.proof_plaintext.ok_or(TestNonceVaultError)?)
                .map_err(|_| TestNonceVaultError)
        }
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
    fn vault_backed_nonce_material_is_sealed_before_commitment_and_restart_stable() {
        let (r_a, r_b) = (share(3), share(5));
        let statement = statement(&r_a, &r_b);
        let mut vault = TestNonceVault::default();
        let (pending, commitment) =
            PendingCommonNonce::new_vault_backed_v1(&statement, 0, &r_a, &mut vault)
                .expect("sealed pending nonce");
        assert_eq!(vault.seal_count, 1);
        assert_eq!(vault.open_count, 1);
        assert_eq!(
            vault.binding.as_ref().expect("binding").statement_hash(),
            &statement.statement_hash()
        );
        let reveal = pending.reveal_bytes();
        let mut restarted_vault = TestNonceVault {
            binding: vault.binding.clone(),
            plaintext: vault.plaintext,
            seal_count: 1,
            ..TestNonceVault::default()
        };
        let (restarted, restarted_commitment) =
            PendingCommonNonce::resume_vault_backed_v1(&statement, 0, &r_a, &mut restarted_vault)
                .expect("restart from authenticated material");
        assert_eq!(restarted_commitment, commitment);
        assert_eq!(restarted.reveal_bytes().as_ref(), reveal.as_ref());

        let mut wrong_share_vault = TestNonceVault::default();
        assert!(PendingCommonNonce::new_vault_backed_v1(
            &statement,
            0,
            &r_b,
            &mut wrong_share_vault,
        )
        .is_err());
        assert_eq!(wrong_share_vault.seal_count, 0);
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
        let share_a = BpRound1ShareV1::new(
            &statement,
            0,
            share(7).public_key().clone(),
            share(9).public_key().clone(),
        )
        .expect("share A");
        let share_b = BpRound1ShareV1::new(
            &statement,
            1,
            share(11).public_key().clone(),
            share(13).public_key().clone(),
        )
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
        let mut vault_a = TestNonceVault::default();
        let mut vault_b = TestNonceVault::default();

        // Rodada 0A: commitments first, reveals only after both are accepted.
        let (pending_a, commit_a) =
            PendingCommonNonce::new_vault_backed_v1(&statement, 0, &r_a, &mut vault_a)
                .expect("persisted pending A");
        let (pending_b, commit_b) =
            PendingCommonNonce::new_vault_backed_v1(&statement, 1, &r_b, &mut vault_b)
                .expect("persisted pending B");
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

        // Rodada 2: each exact tau_x share is encrypted and its nonce record is
        // tombstoned before one send-attempt authority exists.
        let transport_a = driver_a
            .round2_vault_backed_v1(&statement, &local_a, &aggregate_r1, &mut vault_a)
            .expect("durable round2 A");
        let transport_b = driver_b
            .round2_vault_backed_v1(&statement, &local_b, &aggregate_r1, &mut vault_b)
            .expect("durable round2 B");
        assert!(vault_a.plaintext.is_none());
        assert!(vault_b.plaintext.is_none());
        assert!(vault_a.round2_consumed && vault_b.round2_consumed);
        assert_eq!(vault_a.round2_persist_count, 1);
        assert_eq!(vault_b.round2_persist_count, 1);
        let round2_a_bytes = transport_a.into_zeroizing_bytes();
        let round2_a =
            BpRound2ShareV1::from_bytes(round2_a_bytes.as_ref(), &statement).expect("A share");
        let round2_b_digest = *transport_b.message_digest();
        let round2_b_bytes = transport_b.into_zeroizing_bytes();
        let round2_b_received =
            BpRound2ShareV1::from_bytes(round2_b_bytes.as_ref(), &statement).expect("B share");
        let retransmission = driver_b
            .resume_persisted_round2_v1(&statement, 1, &mut vault_b)
            .expect("ACK-loss retransmission without nonce reopen");
        assert_eq!(retransmission.message_digest(), &round2_b_digest);
        assert_eq!(
            retransmission.into_zeroizing_bytes().as_ref(),
            round2_b_bytes.as_ref()
        );
        assert_eq!(vault_b.round2_open_count, 1);
        assert!(vault_b.plaintext.is_none());

        // Crash both processes immediately after round 2. A fresh driver for
        // party A reopens only the retained finalizer continuation (the nonce
        // is already tombstoned), finalizes, verifies, and persists the proof
        // before the continuation is retired.
        let aggregate_r2 = AggregateBpRound2::new(&statement, vec![round2_a, round2_b_received])
            .expect("aggregate round 2");
        let restarted_driver_a =
            DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("restart A");
        let original_finalize = Zeroizing::new(
            vault_a
                .finalize_plaintext
                .as_ref()
                .expect("durable finalizer")
                .as_slice()
                .to_vec(),
        );
        vault_a
            .finalize_plaintext
            .as_mut()
            .expect("durable finalizer")[14] ^= 1;
        assert!(restarted_driver_a
            .finalize_vault_backed_v1(&statement, 0, &aggregate_r1, &aggregate_r2, &mut vault_a)
            .is_err());
        vault_a.finalize_plaintext = Some(Zeroizing::new(original_finalize.as_slice().to_vec()));
        let proof_transport = restarted_driver_a
            .finalize_vault_backed_v1(&statement, 0, &aggregate_r1, &aggregate_r2, &mut vault_a)
            .expect("restart-safe durable finalize");
        let proof_digest = *proof_transport.proof_digest();
        let proof = proof_transport.into_proof();
        assert_eq!(proof.as_bytes().len(), 739);
        assert_eq!(vault_a.finalize_open_count, 2);
        assert_eq!(vault_a.proof_persist_count, 1);
        assert!(vault_a.finalize_plaintext.is_none());
        assert!(vault_a.finalize_consumed);

        // A second process restart reopens only the immutable verified proof;
        // neither original nonce nor finalizer continuation is restored.
        let restarted_again =
            DomCollaborativeRangeProofV1::new(&statement, CAPSULE.to_vec()).expect("restart A2");
        let proof_retransmission = restarted_again
            .resume_persisted_proof_v1(&statement, 0, &aggregate_r1, &mut vault_a)
            .expect("restart proof retransmission");
        assert_eq!(proof_retransmission.proof_digest(), &proof_digest);
        assert_eq!(
            proof_retransmission.into_proof().as_bytes(),
            proof.as_bytes()
        );
        assert_eq!(vault_a.proof_open_count, 1);
        assert!(vault_a.plaintext.is_none());
        assert!(vault_a.finalize_plaintext.is_none());

        // Both parties can run the exit verification independently.
        restarted_driver_a
            .verify_final(&statement, &proof)
            .expect("verify A");
        driver_b.verify_final(&statement, &proof).expect("verify B");
        // And it is the exact consensus call shape for a capsule output.
        assert!(range_proof_verify_with_extra_commit(
            &statement.aggregate_commitment().to_compressed_bytes(),
            proof.as_bytes(),
            &CAPSULE,
        )
        .expect("DOM verifier"));

        // One-shot finalization: the aggregate was consumed and the finalizer
        // is terminally retired in the Store.
        assert!(restarted_driver_a
            .finalize_vault_backed_v1(&statement, 0, &aggregate_r1, &aggregate_r2, &mut vault_a)
            .is_err());
    }
}
