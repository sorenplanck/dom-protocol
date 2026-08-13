//! Crash-durable custody boundary for collaborative Bulletproof nonces.
//!
//! The Master Specification requires the rodada-0A contribution `q_i` and the
//! participant backend `private_nonce_i` to be generated independently by the
//! operating-system CSPRNG and persisted in encrypted short-lived storage
//! before any public commitment is exposed. This module deliberately defines
//! no deterministic derivation, raw public constructor, raw accessor, generic
//! serialization, or reusable import/seal authority.

use crate::bulletproof_mpc::{
    participant_finalize_continuation_from_bytes_v1, participant_finalize_continuation_to_bytes_v1,
    BpParticipantFinalizeStateV1,
};
use crate::{AdaptorError, BpRound2ShareV1, BpStatementV1, RangeProof739, Result};
use core::fmt;
use dom_crypto::{blake2b_256, range_proof_verify_with_extra_commit, scalar_bytes_are_canonical};
use rand_core::{OsRng, RngCore};
use std::error::Error;
use zeroize::{Zeroize, Zeroizing};

const MATERIAL_LEN: usize = 64;
const ROUND2_SHARE_LEN: usize = BpRound2ShareV1::ENCODED_LEN;
const PROOF_LEN: usize = dom_crypto::RANGE_PROOF_SIZE;

/// Public, versioned identity of one short-lived collaborative-BP nonce record.
///
/// The DOM Contracts store additionally binds its own record revision and
/// monotonic stage. These fields are sufficient to prevent a record from being
/// opened for another chain/session/statement/participant position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollaborativeBpNonceBindingV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    statement_hash: [u8; 32],
    participant_id: [u8; 32],
    participant_index: u16,
}

impl CollaborativeBpNonceBindingV1 {
    /// Derive the complete record identity from one canonical statement and
    /// its authenticated roster position.
    pub fn from_statement(statement: &BpStatementV1, participant_index: u16) -> Result<Self> {
        let participant_id = *statement
            .participant_ids()
            .get(usize::from(participant_index))
            .ok_or(AdaptorError::InvalidContext(
                "collaborative BP nonce participant index is outside the statement",
            ))?;
        let statement_bytes = statement.to_bytes();
        let chain_id = statement_bytes[6..38]
            .try_into()
            .map_err(|_| AdaptorError::InvalidContext("invalid BP statement chain binding"))?;
        let session_id = statement_bytes[38..70]
            .try_into()
            .map_err(|_| AdaptorError::InvalidContext("invalid BP statement session binding"))?;
        Ok(Self {
            chain_id,
            session_id,
            statement_hash: statement.statement_hash(),
            participant_id,
            participant_index,
        })
    }

    /// Canonical chain identity copied from the statement.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Canonical session identity copied from the statement.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Domain-separated hash of the complete canonical BP statement.
    pub const fn statement_hash(&self) -> &[u8; 32] {
        &self.statement_hash
    }

    /// Authenticated participant identity at the bound roster position.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }

    /// Authenticated participant position in the frozen statement roster.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Canonical versioned associated data for the nonce and round-2 records.
    pub fn to_aad_bytes(&self) -> [u8; 140] {
        let mut bytes = [0u8; 140];
        bytes[..8].copy_from_slice(b"DOMBPNV1");
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&self.chain_id);
        bytes[42..74].copy_from_slice(&self.session_id);
        bytes[74..106].copy_from_slice(&self.statement_hash);
        bytes[106..138].copy_from_slice(&self.participant_id);
        bytes[138..140].copy_from_slice(&self.participant_index.to_le_bytes());
        bytes
    }

    /// Digest of the complete versioned vault binding.
    pub fn binding_digest_v1(&self) -> [u8; 32] {
        *blake2b_256(&self.to_aad_bytes()).as_bytes()
    }
}

/// Complete public binding of one participant's crash-durable finalizer.
///
/// Besides the nonce-record identity, this binds the exact aggregated round-1
/// points and the exact public `extra_commit` bytes. Consequently a retained
/// continuation cannot be substituted across participants, sessions,
/// statements, recovery capsules, or alternate round-1 aggregates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollaborativeBpFinalizeBindingV1 {
    nonce_binding: CollaborativeBpNonceBindingV1,
    aggregate_t_one: [u8; 33],
    aggregate_t_two: [u8; 33],
    extra_commit: Vec<u8>,
}

impl CollaborativeBpFinalizeBindingV1 {
    pub(crate) fn new(
        nonce_binding: &CollaborativeBpNonceBindingV1,
        statement: &BpStatementV1,
        aggregate_t_one: [u8; 33],
        aggregate_t_two: [u8; 33],
        extra_commit: &[u8],
    ) -> Result<Self> {
        let expected_nonce = CollaborativeBpNonceBindingV1::from_statement(
            statement,
            nonce_binding.participant_index,
        )?;
        if expected_nonce != *nonce_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let expected_recovery = if extra_commit.is_empty() {
            crate::bulletproof_mpc::no_recovery_sentinel_v1()
        } else {
            *blake2b_256(extra_commit).as_bytes()
        };
        if statement.recovery_binding_hash() != &expected_recovery {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        if extra_commit.len() > u16::MAX as usize {
            return Err(AdaptorError::InvalidContext(
                "collaborative BP finalizer extra_commit exceeds the V1 custody bound",
            ));
        }
        dom_crypto::PublicKey::from_compressed_bytes(&aggregate_t_one)?;
        dom_crypto::PublicKey::from_compressed_bytes(&aggregate_t_two)?;
        Ok(Self {
            nonce_binding: nonce_binding.clone(),
            aggregate_t_one,
            aggregate_t_two,
            extra_commit: extra_commit.to_vec(),
        })
    }

    /// Identity of the nonce record atomically retired at round 2.
    pub const fn nonce_binding(&self) -> &CollaborativeBpNonceBindingV1 {
        &self.nonce_binding
    }

    /// Canonical compressed aggregate `T1` from the accepted round-1 vector.
    pub const fn aggregate_t_one(&self) -> &[u8; 33] {
        &self.aggregate_t_one
    }

    /// Canonical compressed aggregate `T2` from the accepted round-1 vector.
    pub const fn aggregate_t_two(&self) -> &[u8; 33] {
        &self.aggregate_t_two
    }

    /// Exact public recovery/decoy capsule bytes bound by the proof.
    pub fn extra_commit(&self) -> &[u8] {
        &self.extra_commit
    }

    /// Canonical versioned associated data for continuation and proof records.
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(220 + self.extra_commit.len());
        bytes.extend_from_slice(b"DOMBPFV1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&self.nonce_binding.to_aad_bytes());
        bytes.extend_from_slice(&self.aggregate_t_one);
        bytes.extend_from_slice(&self.aggregate_t_two);
        let extra_len = u32::try_from(self.extra_commit.len())
            .unwrap_or_else(|_| unreachable!("constructor enforces the u16 V1 bound"));
        bytes.extend_from_slice(&extra_len.to_le_bytes());
        bytes.extend_from_slice(&self.extra_commit);
        bytes
    }

    /// Digest of the complete versioned continuation/proof binding.
    pub fn binding_digest_v1(&self) -> [u8; 32] {
        *blake2b_256(&self.to_aad_bytes()).as_bytes()
    }
}

/// Opaque one-shot collaborative-BP finalizer reconstructed from authenticated
/// retained storage.
///
/// This type has no raw accessor, constructor, codec, clone, copy, debug, or
/// display implementation. Only driver-created persistence/import capabilities
/// can convert between it and temporary zeroizing vault plaintext.
pub struct CollaborativeBpFinalizeContinuationV1 {
    state: BpParticipantFinalizeStateV1,
}

impl CollaborativeBpFinalizeContinuationV1 {
    pub(crate) const fn new(state: BpParticipantFinalizeStateV1) -> Self {
        Self { state }
    }

    pub(crate) fn into_state(self) -> BpParticipantFinalizeStateV1 {
        self.state
    }
}

/// Opaque one-shot ownership of `q_i || private_nonce_i`.
///
/// This type deliberately implements no `Clone`, `Copy`, `Debug`, `Display`,
/// equality, ordering, or generic serialization. Both halves are zeroized on
/// every drop path. Only the integrated driver can generate it, and only a
/// capability handed to the statically selected vault can expose the temporary
/// plaintext needed for authenticated encryption.
pub struct CollaborativeBpNonceMaterialV1 {
    bytes: Zeroizing<[u8; MATERIAL_LEN]>,
}

impl CollaborativeBpNonceMaterialV1 {
    pub(crate) fn generate_from_os_rng() -> Result<Self> {
        // These are intentionally two independent CSPRNG requests. In
        // particular, private_nonce_i is not derived from q_i, the common
        // nonce, a seed, or any public statement field.
        let mut common_reveal = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(common_reveal.as_mut())
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        let mut private_nonce = Zeroizing::new([0u8; 32]);
        loop {
            OsRng
                .try_fill_bytes(private_nonce.as_mut())
                .map_err(|_| AdaptorError::RandomnessFailure)?;
            if scalar_bytes_are_canonical(&private_nonce, false) {
                break;
            }
        }
        let mut bytes = Zeroizing::new([0u8; MATERIAL_LEN]);
        bytes[..32].copy_from_slice(common_reveal.as_ref());
        bytes[32..].copy_from_slice(private_nonce.as_ref());
        Ok(Self { bytes })
    }

    pub(crate) fn into_parts(mut self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        let mut common_reveal = Zeroizing::new([0u8; 32]);
        let mut private_nonce = Zeroizing::new([0u8; 32]);
        common_reveal.copy_from_slice(&self.bytes[..32]);
        private_nonce.copy_from_slice(&self.bytes[32..]);
        self.bytes.zeroize();
        (common_reveal, private_nonce)
    }
}

/// One-shot authority for the selected vault to seal freshly generated BP
/// material. Ordinary callers cannot construct this capability.
pub struct CollaborativeBpNonceSealCapabilityV1 {
    _private: (),
}

impl CollaborativeBpNonceSealCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Consume both the capability and material into one zeroizing plaintext.
    pub fn into_plaintext(
        self,
        material: CollaborativeBpNonceMaterialV1,
    ) -> Zeroizing<[u8; MATERIAL_LEN]> {
        material.bytes
    }
}

/// One-shot authority for the selected vault to return AEAD-authenticated BP
/// material to the integrated driver. Ordinary callers cannot construct it.
pub struct CollaborativeBpNonceImportCapabilityV1 {
    _private: (),
}

impl CollaborativeBpNonceImportCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Consume authenticated decrypted bytes into opaque validated material.
    ///
    /// `q_i` is a 32-byte CSPRNG contribution, not a scalar. The independently
    /// generated backend nonce must be canonical and nonzero.
    pub fn import(
        self,
        mut plaintext: Zeroizing<[u8; MATERIAL_LEN]>,
    ) -> Result<CollaborativeBpNonceMaterialV1> {
        let private_nonce: &[u8; 32] =
            (&plaintext[32..])
                .try_into()
                .map_err(|_| AdaptorError::InvalidLength {
                    object: "CollaborativeBpNonceMaterialV1 private nonce",
                    expected: 32,
                    actual: plaintext.len().saturating_sub(32),
                })?;
        if !scalar_bytes_are_canonical(private_nonce, false) {
            plaintext.zeroize();
            return Err(AdaptorError::InvalidContext(
                "collaborative BP private nonce must be canonical and nonzero",
            ));
        }
        Ok(CollaborativeBpNonceMaterialV1 { bytes: plaintext })
    }
}

/// One-shot authority that lets only the selected vault consume a generated
/// round-2 share for durable encrypted persistence.
///
/// The capability is driver-created and binds the exact statement and
/// participant record. It has no public constructor, codec, clone, copy, or
/// debug implementation.
pub struct CollaborativeBpRound2PersistenceCapabilityV1 {
    binding: CollaborativeBpFinalizeBindingV1,
    statement: BpStatementV1,
}

impl CollaborativeBpRound2PersistenceCapabilityV1 {
    pub(crate) fn new(
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
    ) -> Self {
        Self {
            binding: binding.clone(),
            statement: statement.clone(),
        }
    }

    /// Consume the generated share into a zeroizing persistence buffer and
    /// return the only authority able to authenticate that same byte string
    /// after the vault's atomic write-and-tombstone transaction.
    pub fn into_plaintext(
        self,
        continuation: CollaborativeBpFinalizeContinuationV1,
        share: BpRound2ShareV1,
    ) -> Result<(
        Zeroizing<Vec<u8>>,
        Zeroizing<[u8; ROUND2_SHARE_LEN]>,
        CollaborativeBpFinalizeImportCapabilityV1,
        CollaborativeBpRound2ImportCapabilityV1,
    )> {
        let expected_binding = CollaborativeBpNonceBindingV1::from_statement(
            &self.statement,
            self.binding.nonce_binding.participant_index,
        )?;
        if expected_binding != self.binding.nonce_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let continuation_bytes = participant_finalize_continuation_to_bytes_v1(
            continuation.into_state(),
            &self.statement,
            self.binding.nonce_binding.participant_index,
        )?;
        let bytes = share.into_zeroizing_bytes();
        BpRound2ShareV1::from_bytes(bytes.as_ref(), &self.statement)?;
        let message_digest = round2_message_digest_v1(&self.binding.nonce_binding, &*bytes);
        Ok((
            continuation_bytes,
            bytes,
            CollaborativeBpFinalizeImportCapabilityV1 {
                binding: self.binding.clone(),
            },
            CollaborativeBpRound2ImportCapabilityV1 {
                binding: self.binding.nonce_binding,
                expected_message_digest: Some(message_digest),
            },
        ))
    }
}

/// One-shot authority for authenticated reconstruction of an encrypted
/// finalizer continuation. Ordinary callers cannot construct it.
pub struct CollaborativeBpFinalizeImportCapabilityV1 {
    binding: CollaborativeBpFinalizeBindingV1,
}

impl CollaborativeBpFinalizeImportCapabilityV1 {
    pub(crate) fn for_restart(binding: &CollaborativeBpFinalizeBindingV1) -> Self {
        Self {
            binding: binding.clone(),
        }
    }

    /// Import authenticated continuation plaintext and revalidate every secret
    /// and public relation against the exact statement and aggregate round 1.
    pub fn import(
        self,
        statement: &BpStatementV1,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<CollaborativeBpFinalizeContinuationV1> {
        let expected_nonce = CollaborativeBpNonceBindingV1::from_statement(
            statement,
            self.binding.nonce_binding.participant_index,
        )?;
        if expected_nonce != self.binding.nonce_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let state = participant_finalize_continuation_from_bytes_v1(
            plaintext,
            statement,
            self.binding.nonce_binding.participant_index,
            &self.binding.aggregate_t_one,
            &self.binding.aggregate_t_two,
            &self.binding.extra_commit,
        )?;
        Ok(CollaborativeBpFinalizeContinuationV1::new(state))
    }
}

/// One-shot authority for authenticated import of the immutable encrypted
/// round-2 artifact.
///
/// The immediate persistence path binds the exact digest generated before the
/// Store transaction. The restart/retry path instead trusts only an
/// AEAD-authenticated artifact whose binding and digest are revalidated here.
pub struct CollaborativeBpRound2ImportCapabilityV1 {
    binding: CollaborativeBpNonceBindingV1,
    expected_message_digest: Option<[u8; 32]>,
}

impl CollaborativeBpRound2ImportCapabilityV1 {
    pub(crate) fn for_restart(binding: &CollaborativeBpNonceBindingV1) -> Self {
        Self {
            binding: binding.clone(),
            expected_message_digest: None,
        }
    }

    /// Import exact AEAD-authenticated bytes only when they remain bound to the
    /// canonical statement, participant, and (for the initial persist) the
    /// generated message digest.
    pub fn import(
        self,
        statement: &BpStatementV1,
        plaintext: Zeroizing<[u8; ROUND2_SHARE_LEN]>,
    ) -> Result<DurableBpRound2TransportV1> {
        let expected_binding = CollaborativeBpNonceBindingV1::from_statement(
            statement,
            self.binding.participant_index,
        )?;
        if expected_binding != self.binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        BpRound2ShareV1::from_bytes(plaintext.as_ref(), statement)?;
        let message_digest = round2_message_digest_v1(&self.binding, &*plaintext);
        if self
            .expected_message_digest
            .is_some_and(|expected| expected != message_digest)
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(DurableBpRound2TransportV1 {
            binding: self.binding,
            message_digest,
            bytes: plaintext,
        })
    }
}

/// One send-attempt authority over an already durable round-2 artifact.
///
/// This value contains no original BP nonce. It yields one zeroizing exact
/// 104-byte buffer and is then consumed. ACK-loss retransmission obtains a new
/// authority by reopening the immutable encrypted artifact; the consumed nonce
/// record is never opened or recreated.
pub struct DurableBpRound2TransportV1 {
    binding: CollaborativeBpNonceBindingV1,
    message_digest: [u8; 32],
    bytes: Zeroizing<[u8; ROUND2_SHARE_LEN]>,
}

impl DurableBpRound2TransportV1 {
    /// Complete statement/session/participant binding authenticated by Store.
    pub const fn binding(&self) -> &CollaborativeBpNonceBindingV1 {
        &self.binding
    }

    /// Digest of the exact bound round-2 message bytes.
    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    /// Consume this send-attempt authority into exact zeroizing transport
    /// bytes. A retry must reopen the durable artifact through the vault.
    pub fn into_zeroizing_bytes(self) -> Zeroizing<[u8; ROUND2_SHARE_LEN]> {
        self.bytes
    }
}

/// One-shot authority allowing the selected vault to persist a fully verified
/// proof before retiring its finalizer continuation.
pub struct CollaborativeBpProofPersistenceCapabilityV1 {
    binding: CollaborativeBpFinalizeBindingV1,
    statement: BpStatementV1,
}

impl CollaborativeBpProofPersistenceCapabilityV1 {
    pub(crate) fn new(
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
    ) -> Self {
        Self {
            binding: binding.clone(),
            statement: statement.clone(),
        }
    }

    /// Consume a verified proof into exact persistence bytes and the sole
    /// authority able to authenticate the retained artifact.
    pub fn into_plaintext(
        self,
        proof: RangeProof739,
    ) -> Result<([u8; PROOF_LEN], CollaborativeBpProofImportCapabilityV1)> {
        let expected_nonce = CollaborativeBpNonceBindingV1::from_statement(
            &self.statement,
            self.binding.nonce_binding.participant_index,
        )?;
        if expected_nonce != self.binding.nonce_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let accepted = range_proof_verify_with_extra_commit(
            &self.statement.aggregate_commitment().to_compressed_bytes(),
            proof.as_bytes(),
            &self.binding.extra_commit,
        )?;
        if !accepted {
            return Err(AdaptorError::VerificationFailed(
                "persisted collaborative proof failed the DOM verifier",
            ));
        }
        let bytes = *proof.as_bytes();
        let proof_digest = proof_message_digest_v1(&self.binding, &bytes);
        Ok((
            bytes,
            CollaborativeBpProofImportCapabilityV1 {
                binding: self.binding,
                expected_proof_digest: Some(proof_digest),
            },
        ))
    }
}

/// One-shot authority for authenticated import of a persisted verified proof.
pub struct CollaborativeBpProofImportCapabilityV1 {
    binding: CollaborativeBpFinalizeBindingV1,
    expected_proof_digest: Option<[u8; 32]>,
}

impl CollaborativeBpProofImportCapabilityV1 {
    pub(crate) fn for_restart(binding: &CollaborativeBpFinalizeBindingV1) -> Self {
        Self {
            binding: binding.clone(),
            expected_proof_digest: None,
        }
    }

    /// Validate exact retained proof bytes and create one post-persistence
    /// transport authority.
    pub fn import(
        self,
        statement: &BpStatementV1,
        plaintext: [u8; PROOF_LEN],
    ) -> Result<DurableBpProofTransportV1> {
        let expected_nonce = CollaborativeBpNonceBindingV1::from_statement(
            statement,
            self.binding.nonce_binding.participant_index,
        )?;
        if expected_nonce != self.binding.nonce_binding {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        let accepted = range_proof_verify_with_extra_commit(
            &statement.aggregate_commitment().to_compressed_bytes(),
            &plaintext,
            &self.binding.extra_commit,
        )?;
        if !accepted {
            return Err(AdaptorError::VerificationFailed(
                "retained collaborative proof failed the DOM verifier",
            ));
        }
        let proof_digest = proof_message_digest_v1(&self.binding, &plaintext);
        if self
            .expected_proof_digest
            .is_some_and(|expected| expected != proof_digest)
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(DurableBpProofTransportV1 {
            binding: self.binding,
            proof_digest,
            proof: RangeProof739::try_from(plaintext.as_slice())?,
        })
    }
}

/// One-use authority over an already persisted and verified final proof.
///
/// The proof becomes available to output construction only after the Store has
/// committed it and retired the corresponding secret continuation. ACK-loss or
/// restart obtains another authority by reopening the immutable proof record.
pub struct DurableBpProofTransportV1 {
    binding: CollaborativeBpFinalizeBindingV1,
    proof_digest: [u8; 32],
    proof: RangeProof739,
}

impl DurableBpProofTransportV1 {
    /// Complete statement/participant/aggregate-round-1 binding.
    pub const fn binding(&self) -> &CollaborativeBpFinalizeBindingV1 {
        &self.binding
    }

    /// Digest of the exact retained 739-byte proof.
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }

    /// Consume this authority into the exact consensus proof container.
    pub fn into_proof(self) -> RangeProof739 {
        self.proof
    }
}

fn round2_message_digest_v1(
    binding: &CollaborativeBpNonceBindingV1,
    bytes: &[u8; ROUND2_SHARE_LEN],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + 32 + ROUND2_SHARE_LEN);
    input.extend_from_slice(b"DOMBPR21");
    input.extend_from_slice(&binding.binding_digest_v1());
    input.extend_from_slice(bytes);
    *blake2b_256(&input).as_bytes()
}

fn proof_message_digest_v1(
    binding: &CollaborativeBpFinalizeBindingV1,
    bytes: &[u8; PROOF_LEN],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + 32 + PROOF_LEN);
    input.extend_from_slice(b"DOMBPPF1");
    input.extend_from_slice(&binding.binding_digest_v1());
    input.extend_from_slice(bytes);
    *blake2b_256(&input).as_bytes()
}

/// Statically selected encrypted short-lived store for collaborative BP nonce
/// material.
///
/// Implementations must authenticate the complete [`CollaborativeBpNonceBindingV1`],
/// enforce an immutable monotonic stage journal, reject replacement and
/// rollback, and never include this short-lived record in a backup. The first
/// method must durably seal and sync before returning. The second method may
/// return plaintext only after AEAD and binding validation and must enforce its
/// store-owned one-shot/stage policy. The driver releases no public commitment
/// before both operations succeed.
pub trait CollaborativeBpNonceVaultV1: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Seal one fresh record. An existing binding must fail closed rather than
    /// overwrite, reset, or silently resume it.
    fn seal_fresh_material(
        &mut self,
        binding: &CollaborativeBpNonceBindingV1,
        material: CollaborativeBpNonceMaterialV1,
        capability: CollaborativeBpNonceSealCapabilityV1,
    ) -> core::result::Result<(), Self::Error>;

    /// Open the exact already-persisted record under store-owned stage
    /// authority. A missing, replaced, rolled-back, consumed, or differently
    /// bound record must fail closed.
    fn open_persisted_material(
        &mut self,
        binding: &CollaborativeBpNonceBindingV1,
        capability: CollaborativeBpNonceImportCapabilityV1,
    ) -> core::result::Result<CollaborativeBpNonceMaterialV1, Self::Error>;

    /// Atomically persist the exact encrypted round-2 share and encrypted
    /// finalizer continuation, then retire the BP nonce record before returning
    /// any transport authority.
    ///
    /// Implementations must use `capability.into_plaintext`, commit the
    /// immutable bound artifact and a terminal consumed tombstone (removing the
    /// nonce material) in one retained-store transaction, fsync, read and
    /// authenticate the artifact, then use the returned import capability.
    /// Returning before all of those steps is forbidden.
    fn persist_round2_and_consume_material(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        continuation: CollaborativeBpFinalizeContinuationV1,
        share: BpRound2ShareV1,
        capability: CollaborativeBpRound2PersistenceCapabilityV1,
    ) -> core::result::Result<DurableBpRound2TransportV1, Self::Error>;

    /// Reopen a one-shot byte-identical retransmission authority from the
    /// immutable encrypted round-2 artifact after restart or ACK loss.
    ///
    /// This method must require the terminal consumed tombstone and must never
    /// open, restore, or derive the original BP nonce material.
    fn open_persisted_round2(
        &mut self,
        binding: &CollaborativeBpNonceBindingV1,
        statement: &BpStatementV1,
        capability: CollaborativeBpRound2ImportCapabilityV1,
    ) -> core::result::Result<DurableBpRound2TransportV1, Self::Error>;

    /// Open the authenticated encrypted finalizer continuation after restart.
    ///
    /// The original nonce record must already have its terminal consumed
    /// tombstone. Implementations must not delete or consume the continuation
    /// here: a failed proof computation remains restartable.
    fn open_persisted_finalize_continuation(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        capability: CollaborativeBpFinalizeImportCapabilityV1,
    ) -> core::result::Result<CollaborativeBpFinalizeContinuationV1, Self::Error>;

    /// Atomically persist and fsync the exact verified 739-byte proof, then
    /// tombstone and delete the secret finalizer continuation before returning.
    ///
    /// Implementations must use `capability.into_plaintext`, commit proof and
    /// continuation retirement in one retained-store transaction, re-read and
    /// authenticate the proof, and only then use the returned import authority.
    fn persist_verified_proof_and_consume_finalize(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        proof: RangeProof739,
        capability: CollaborativeBpProofPersistenceCapabilityV1,
    ) -> core::result::Result<DurableBpProofTransportV1, Self::Error>;

    /// Reopen an immutable already-verified proof after restart or ACK loss.
    ///
    /// This method must require the terminal finalizer-consumed marker and must
    /// never restore or reopen either the finalizer continuation or BP nonce.
    fn open_persisted_proof(
        &mut self,
        binding: &CollaborativeBpFinalizeBindingV1,
        statement: &BpStatementV1,
        capability: CollaborativeBpProofImportCapabilityV1,
    ) -> core::result::Result<DurableBpProofTransportV1, Self::Error>;
}

/// Failure from the integrated BP driver/vault boundary.
#[derive(Debug)]
pub enum CollaborativeBpNonceVaultError<E> {
    /// Canonical DOM input, randomness, or cryptographic validation failed.
    Protocol(AdaptorError),
    /// The selected durable vault failed closed.
    Vault(E),
}

impl<E: fmt::Display> fmt::Display for CollaborativeBpNonceVaultError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "collaborative BP protocol error: {error}"),
            Self::Vault(_) => {
                formatter.write_str("collaborative BP nonce vault rejected operation")
            }
        }
    }
}

impl<E: Error + Send + Sync + 'static> Error for CollaborativeBpNonceVaultError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Vault(error) => Some(error),
        }
    }
}
