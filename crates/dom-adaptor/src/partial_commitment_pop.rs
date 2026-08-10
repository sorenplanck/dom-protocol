//! Proof of knowledge for a partial blinding commitment `C_j = r_j*G`.
//!
//! Phase 2 deliverable 4 of the implementation schedule. When two parties
//! blind a shared output, each contributes a commitment share `C_j`, and the
//! aggregate is validated to sum to the target. Summing to the target is not
//! enough: a party can pick `C_j = C_target - C_other` — a point it does not
//! know the opening of — and cancel the counterparty's contribution by
//! grinding. This is the Mimblewimble rogue-key gap the DOM must not inherit.
//!
//! Closing it requires each party to prove knowledge of the scalar `r_j`
//! behind its `C_j`. This module provides that Schnorr proof, bound to the
//! collaborative Bulletproof statement so a proof cannot be replayed onto a
//! different session, participant, or commitment share. It reuses the
//! authoritative DOM scalar and point helpers; it introduces no arithmetic.

use crate::{bulletproof_mpc::BpStatementV1, error::exact_array, AdaptorError, Result};
use dom_crypto::{
    blake2b_256_tagged, scalar_bytes_are_canonical, scalar_from_wide_be,
    secret_scalar_mul_add_assign, secret_scalar_public_key, verify_scalar_response, PublicKey,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const CHALLENGE_TAG_V1: &str = "DOM:scriptless-partial-commit-pop-challenge:v1";
const CONTEXT_TAG_V1: &str = "DOM:scriptless-partial-commit-pop-context:v1";

/// Opaque partial blinding scalar `r_j` behind a commitment share.
///
/// This is not a signing share: conflating the two secrets would let a proof
/// authorize the wrong operation, so the type is distinct. It implements no
/// clone, copy, debug, display, equality, ordering, or generic serialization,
/// and its bytes are zeroized on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct PartialBlindingV1 {
    bytes: [u8; 32],
}

impl PartialBlindingV1 {
    /// Parse a canonical nonzero big-endian blinding scalar.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self> {
        if !scalar_bytes_are_canonical(&bytes, false) {
            return Err(AdaptorError::InvalidContext(
                "partial blinding must be a canonical nonzero scalar",
            ));
        }
        Ok(Self { bytes })
    }

    /// Derive the commitment share `C_j = r_j*G`.
    pub fn commitment_share(&self) -> Result<PublicKey> {
        secret_scalar_public_key(&self.bytes).map_err(Into::into)
    }
}

/// Exact 65-byte Schnorr proof of knowledge for one partial commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialCommitmentProofV1 {
    commitment: PublicKey,
    response: [u8; 32],
}

impl PartialCommitmentProofV1 {
    /// Canonical proof length.
    pub const ENCODED_LEN: usize = 65;

    /// Parse an exact proof, rejecting noncanonical points or response scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("PartialCommitmentProofV1", bytes)?;
        let commitment_bytes =
            exact_array::<33>("PartialCommitmentProofV1 commitment", &bytes[..33])?;
        let commitment = PublicKey::from_compressed_bytes(&commitment_bytes)?;
        if commitment.to_compressed_bytes() != commitment_bytes {
            return Err(AdaptorError::InvalidContext(
                "partial commitment PoK point must re-encode canonically",
            ));
        }
        let response = exact_array::<32>("PartialCommitmentProofV1 response", &bytes[33..])?;
        if !scalar_bytes_are_canonical(&response, true) {
            return Err(AdaptorError::InvalidContext(
                "partial commitment PoK response is a noncanonical scalar",
            ));
        }
        Ok(Self {
            commitment,
            response,
        })
    }

    /// Serialize the exact canonical proof.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..33].copy_from_slice(&self.commitment.to_compressed_bytes());
        bytes[33..].copy_from_slice(&self.response);
        bytes
    }

    /// Return the proof commitment.
    pub const fn commitment(&self) -> &PublicKey {
        &self.commitment
    }

    /// Return the canonical response scalar.
    pub const fn response(&self) -> &[u8; 32] {
        &self.response
    }
}

/// Resolve the commitment share `C_j` this participant is bound to prove.
fn bound_commitment_share(statement: &BpStatementV1, participant_index: u16) -> Result<PublicKey> {
    statement
        .commitment_shares()
        .get(usize::from(participant_index))
        .cloned()
        .ok_or(AdaptorError::InvalidContext(
            "partial commitment participant index is outside the statement",
        ))
}

/// Prove knowledge of `r_j` behind this participant's commitment share.
///
/// The blinding must open the exact share the statement records for this
/// participant; a mismatch fails closed before any proving.
pub fn prove_partial_commitment_v1(
    statement: &BpStatementV1,
    participant_index: u16,
    blinding: &PartialBlindingV1,
) -> Result<PartialCommitmentProofV1> {
    let bound_share = bound_commitment_share(statement, participant_index)?;
    if blinding.commitment_share()? != bound_share {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let nonce = random_secret_scalar()?;
    prove_with_nonce(statement, participant_index, &bound_share, blinding, nonce)
}

/// Verify a partial-commitment proof against the statement's recorded share.
pub fn verify_partial_commitment_v1(
    statement: &BpStatementV1,
    participant_index: u16,
    proof: &PartialCommitmentProofV1,
) -> Result<bool> {
    let bound_share = bound_commitment_share(statement, participant_index)?;
    let challenge = challenge_scalar(
        statement,
        participant_index,
        &bound_share,
        proof.commitment(),
    )?;
    verify_scalar_response(
        proof.response(),
        proof.commitment(),
        &challenge,
        &bound_share,
    )
    .map_err(Into::into)
}

/// Require a valid opening proof for every commitment share in the statement.
///
/// This is the joint-blinding enforcement gate. The Bulletproof statement
/// already validates that the commitment shares sum to the aggregate; that
/// alone does not stop a party from contributing a share it cannot open. This
/// requires exactly one proof per participant index, each verifying against the
/// share the statement records, before the aggregate is trusted. Missing,
/// duplicate, out-of-range, or invalid proofs all fail closed.
///
/// The proofs are supplied as `(participant_index, proof)` in any order; the
/// gate reduces them to a per-participant presence set so the caller cannot
/// satisfy the check by repeating one participant's proof.
pub fn verify_all_partial_commitments_v1(
    statement: &BpStatementV1,
    proofs: &[(u16, PartialCommitmentProofV1)],
) -> Result<bool> {
    let participant_count = statement.commitment_shares().len();
    let mut seen = vec![false; participant_count];
    for (participant_index, proof) in proofs {
        let position = usize::from(*participant_index);
        if position >= participant_count {
            return Err(AdaptorError::InvalidContext(
                "partial commitment proof index is outside the statement",
            ));
        }
        if seen[position] {
            return Err(AdaptorError::DuplicateParticipant);
        }
        if !verify_partial_commitment_v1(statement, *participant_index, proof)? {
            return Ok(false);
        }
        seen[position] = true;
    }
    Ok(seen.iter().all(|present| *present))
}

fn random_secret_scalar() -> Result<Zeroizing<[u8; 32]>> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        if scalar_bytes_are_canonical(&bytes, false) {
            return Ok(bytes);
        }
    }
}

fn prove_with_nonce(
    statement: &BpStatementV1,
    participant_index: u16,
    bound_share: &PublicKey,
    blinding: &PartialBlindingV1,
    mut nonce: Zeroizing<[u8; 32]>,
) -> Result<PartialCommitmentProofV1> {
    let commitment = secret_scalar_public_key(&nonce)?;
    let challenge = challenge_scalar(statement, participant_index, bound_share, &commitment)?;
    secret_scalar_mul_add_assign(&mut nonce, &blinding.bytes, &challenge)?;
    let proof = PartialCommitmentProofV1::from_bytes(&{
        let mut bytes = [0u8; PartialCommitmentProofV1::ENCODED_LEN];
        bytes[..33].copy_from_slice(&commitment.to_compressed_bytes());
        bytes[33..].copy_from_slice(nonce.as_ref());
        bytes
    });
    proof
}

fn challenge_scalar(
    statement: &BpStatementV1,
    participant_index: u16,
    bound_share: &PublicKey,
    commitment: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>> {
    // Bind the challenge to the statement, the exact participant, the exact
    // commitment share, and the prover's nonce commitment. Binding the share
    // and participant is what stops a proof from being replayed onto another
    // participant's C_j inside the same session.
    let mut context = Zeroizing::new([0u8; 32 + 2 + 33 + 33]);
    context[..32].copy_from_slice(&statement.statement_hash());
    context[32..34].copy_from_slice(&participant_index.to_le_bytes());
    context[34..67].copy_from_slice(&bound_share.to_compressed_bytes());
    context[67..].copy_from_slice(&commitment.to_compressed_bytes());
    let context_digest = *blake2b_256_tagged(CONTEXT_TAG_V1, context.as_ref()).as_bytes();

    let mut challenge_input = Zeroizing::new([0u8; 36]);
    challenge_input[..32].copy_from_slice(&context_digest);

    let mut counter = 0u32;
    loop {
        challenge_input[32..].copy_from_slice(&counter.to_le_bytes());
        let mut first_input = Zeroizing::new([0u8; 37]);
        first_input[1..].copy_from_slice(challenge_input.as_ref());
        let mut second_input = Zeroizing::new(*first_input);
        second_input[0] = 1;
        let mut first_hash = blake2b_256_tagged(CHALLENGE_TAG_V1, first_input.as_ref());
        let mut second_hash = blake2b_256_tagged(CHALLENGE_TAG_V1, second_input.as_ref());
        let mut wide = Zeroizing::new([0u8; 64]);
        wide[..32].copy_from_slice(first_hash.as_bytes());
        wide[32..].copy_from_slice(second_hash.as_bytes());
        first_hash.zeroize();
        second_hash.zeroize();
        if let Some(challenge) = scalar_from_wide_be(&wide) {
            return Ok(challenge);
        }
        counter = counter
            .checked_add(1)
            .ok_or(AdaptorError::ChallengeCounterOverflow)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustedChainIdV1;

    fn blinding(byte: u8) -> PartialBlindingV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        PartialBlindingV1::from_be_bytes(bytes).expect("small scalar is canonical")
    }

    fn nonce(byte: u8) -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes[31] = byte;
        bytes
    }

    // Build a two-party statement whose recorded commitment shares are the
    // exact openings of the two blindings, so proofs can be checked against
    // the real aggregate the MPC statement validates.
    fn fixture() -> (BpStatementV1, PartialBlindingV1, PartialBlindingV1) {
        let r_a = blinding(7);
        let r_b = blinding(9);
        let c_a = r_a.commitment_share().expect("C_a");
        let c_b = r_b.commitment_share().expect("C_b");
        let aggregate =
            BpStatementV1::aggregate_commitment_from_shares(&[c_a.clone(), c_b.clone()], 42)
                .expect("aggregate");
        let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        let statement = BpStatementV1::new(
            &chain,
            [0x22; 32],
            vec![[0x21; 32], [0x42; 32]],
            42,
            vec![c_a, c_b],
            aggregate,
            Some([0x44; 32]),
        )
        .expect("statement");
        (statement, r_a, r_b)
    }

    #[test]
    fn proof_roundtrips_and_verifies_for_each_participant() {
        let (statement, r_a, r_b) = fixture();
        let proof_a = prove_with_nonce(
            &statement,
            0,
            &r_a.commitment_share().unwrap(),
            &r_a,
            nonce(3),
        )
        .expect("proof A");
        let proof_b = prove_with_nonce(
            &statement,
            1,
            &r_b.commitment_share().unwrap(),
            &r_b,
            nonce(4),
        )
        .expect("proof B");
        assert!(verify_partial_commitment_v1(&statement, 0, &proof_a).unwrap());
        assert!(verify_partial_commitment_v1(&statement, 1, &proof_b).unwrap());
        assert_eq!(
            PartialCommitmentProofV1::from_bytes(&proof_a.to_bytes()).unwrap(),
            proof_a
        );
    }

    #[test]
    fn joint_gate_requires_one_valid_proof_per_participant() {
        let (statement, r_a, r_b) = fixture();
        let proof_a = prove_with_nonce(
            &statement,
            0,
            &r_a.commitment_share().unwrap(),
            &r_a,
            nonce(3),
        )
        .expect("proof A");
        let proof_b = prove_with_nonce(
            &statement,
            1,
            &r_b.commitment_share().unwrap(),
            &r_b,
            nonce(4),
        )
        .expect("proof B");

        // Complete and correct set passes.
        assert!(verify_all_partial_commitments_v1(
            &statement,
            &[(0, proof_a.clone()), (1, proof_b.clone())],
        )
        .unwrap());

        // A missing participant fails closed even though every supplied proof
        // is valid.
        assert!(!verify_all_partial_commitments_v1(&statement, &[(0, proof_a.clone())]).unwrap());

        // Repeating one participant's proof cannot cover for the other.
        assert!(matches!(
            verify_all_partial_commitments_v1(
                &statement,
                &[(0, proof_a.clone()), (0, proof_a.clone())]
            ),
            Err(AdaptorError::DuplicateParticipant)
        ));

        // An out-of-range index fails closed.
        assert!(verify_all_partial_commitments_v1(
            &statement,
            &[(0, proof_a.clone()), (2, proof_b.clone())],
        )
        .is_err());

        // A proof placed under the wrong participant index does not verify.
        assert!(
            !verify_all_partial_commitments_v1(&statement, &[(0, proof_b), (1, proof_a)],).unwrap()
        );
    }

    #[test]
    fn a_proof_does_not_verify_for_the_other_participant() {
        // The rogue-key defense: a proof bound to C_a must not satisfy C_b.
        let (statement, r_a, _) = fixture();
        let proof_a = prove_with_nonce(
            &statement,
            0,
            &r_a.commitment_share().unwrap(),
            &r_a,
            nonce(3),
        )
        .expect("proof A");
        assert!(!verify_partial_commitment_v1(&statement, 1, &proof_a).unwrap());
    }

    #[test]
    fn wrong_blinding_cannot_prove_its_bound_share() {
        let (statement, _, _) = fixture();
        // r=5 does not open the share recorded at index 0 (which is r=7).
        assert!(matches!(
            prove_partial_commitment_v1(&statement, 0, &blinding(5)),
            Err(AdaptorError::AuthorizationMismatch)
        ));
    }

    #[test]
    fn a_cancelling_share_has_no_provable_opening() {
        // The grinding attack: party B publishes a share it cannot open —
        // classically C_b' = C_target - C_a — to cancel A's contribution. Model
        // it directly by recording a share whose scalar B does not hold, and
        // show the honest prover cannot produce a proof for it. Here index 1's
        // recorded share is r_x*G while B only holds r_b != r_x, so proving
        // fails closed: a party that cannot open its published share is stuck.
        let r_a = blinding(7);
        let r_x = blinding(11);
        let r_b_held = blinding(9);
        let c_a = r_a.commitment_share().unwrap();
        let c_x = r_x.commitment_share().unwrap();
        let aggregate =
            BpStatementV1::aggregate_commitment_from_shares(&[c_a.clone(), c_x.clone()], 42)
                .expect("aggregate");
        let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        let statement = BpStatementV1::new(
            &chain,
            [0x22; 32],
            vec![[0x21; 32], [0x42; 32]],
            42,
            vec![c_a, c_x],
            aggregate,
            Some([0x44; 32]),
        )
        .expect("statement");
        // B holds r_b_held, not the r_x that opens the recorded share.
        assert!(matches!(
            prove_partial_commitment_v1(&statement, 1, &r_b_held),
            Err(AdaptorError::AuthorizationMismatch)
        ));
        // And only the true opener r_x can prove it — confirming the gate is
        // not simply rejecting everything.
        assert!(prove_partial_commitment_v1(&statement, 1, &r_x).is_ok());
    }

    #[test]
    fn every_proof_byte_mutation_fails_closed() {
        let (statement, r_a, _) = fixture();
        let proof = prove_with_nonce(
            &statement,
            0,
            &r_a.commitment_share().unwrap(),
            &r_a,
            nonce(3),
        )
        .expect("proof");
        for index in 0..PartialCommitmentProofV1::ENCODED_LEN {
            let mut mutated = proof.to_bytes();
            mutated[index] ^= 1;
            if let Ok(parsed) = PartialCommitmentProofV1::from_bytes(&mutated) {
                assert!(
                    !verify_partial_commitment_v1(&statement, 0, &parsed).unwrap(),
                    "proof mutation {index} verified"
                );
            }
        }
    }
}
