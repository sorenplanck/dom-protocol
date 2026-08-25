//! Joint-blinding session layer for the shared output (spec §§4.2–4.3).
//!
//! This is the session-layer half of the collaborative shared-output driver.
//! Per the master specification
//! `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0`:
//!
//! - §4.2 "Share de blinding": each participant chooses `r_i` and publishes
//!   `R_i = r_i*G`, together with a Schnorr proof of knowledge bound to
//!   `chain_id || session_id || participant_id || role || participant_index ||
//!   R_i || terms_hash || capsule_hash` under the tag
//!   `DOM:scriptless-share-pop:v1`. That primitive is `share_pop.rs`; line 375
//!   of the spec names it "Proof of knowledge do share de blinding/chave". The
//!   proof prevents a knowledge-free contribution and malformed-point attacks.
//! - §4.3 "Commitment agregado": after validating every PoK, the aggregate is
//!   `R_total = Σ R_i` and the shared commitment is `C = v*H + R_total`, with
//!   `R_total` and `C` at infinity rejected.
//! - §1.2: "ninguém precisa conhecer r ... O blinding agregado nunca é
//!   reconstruído." `C` is therefore computed by point addition; the scalar
//!   sum `Σ r_i` is never formed.
//!
//! The Bulletproof range-proof layer (§5, `bulletproof_mpc.rs`) is separate:
//! it proves the range over `[v, MAX-v]` with `blinds_i = [r_i, -r_i]`. Its
//! commitment-share representation is an internal backend concern and is not
//! the object the §4.2 PoK proves. This module is the session-layer gate that
//! precedes it.

use crate::{
    share_pop::{prove_share_knowledge_v1, verify_share_knowledge_v1, SharePoPStatementV1},
    AdaptorError, DirectionV1, Result, ShareProofV1, SigningShareV1, TrustedChainIdV1,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{PublicKey};
use dom_scriptless_primitives::{scriptless_add_public_points};

/// One participant's published blinding share `R_i` and its §4.2 PoK.
///
/// The scalar `r_i` behind `R_i` is carried by the caller as a `SigningShareV1`;
/// per §4.2 this is the blinding-share scalar, and the proof proves knowledge of
/// it. The contribution reveals no secret: only the public point and the proof.
#[derive(Debug, Clone)]
pub struct BlindingShareV1 {
    role: DirectionV1,
    participant_index: u16,
    share_point: PublicKey,
    proof: ShareProofV1,
}

impl BlindingShareV1 {
    /// The participant's published `R_i = r_i*G`.
    pub fn share_point(&self) -> PublicKey {
        self.share_point.clone()
    }

    /// The participant's roster index.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }
}

/// The validated shared commitment `C = v*H + Σ R_i` (§4.3).
///
/// It exposes only the public commitment bytes; the blinding sum is never
/// formed (§1.2), so nothing here can reconstruct it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedCommitmentV1 {
    commitment: [u8; 33],
}

impl SharedCommitmentV1 {
    /// The compressed shared commitment `C`.
    pub const fn commitment_bytes(&self) -> &[u8; 33] {
        &self.commitment
    }
}

/// Produce one participant's §4.2 blinding-share contribution.
///
/// `blinding` carries the participant's blinding scalar `r_i`; its public key is
/// `R_i = r_i*G`. The proof binds the exact §4.2 context. `capsule_hash` is the
/// recovery/decoy capsule hash the session agreed on (the spec's `capsule_hash`,
/// carried as `share_pop`'s `recovery_binding_hash`).
#[allow(clippy::too_many_arguments)]
pub fn contribute_blinding_share_v1(
    chain_id: &TrustedChainIdV1,
    session_id: [u8; 32],
    roster: &[[u8; 32]],
    role: DirectionV1,
    participant_index: u16,
    blinding: &SigningShareV1,
    terms_hash: [u8; 32],
    capsule_hash: [u8; 32],
) -> Result<BlindingShareV1> {
    let share_point = blinding.public_key().clone();
    let statement = SharePoPStatementV1::new(
        chain_id,
        session_id,
        roster,
        role,
        participant_index,
        share_point.clone(),
        terms_hash,
        capsule_hash,
    )?;
    let proof = prove_share_knowledge_v1(&statement, blinding)?;
    Ok(BlindingShareV1 {
        role,
        participant_index,
        share_point,
        proof,
    })
}

/// Validate every §4.2 PoK and compute the shared commitment `C` (§4.3).
///
/// Requires one contribution per roster participant, in ascending index order
/// with no duplicates. Each contribution's proof must verify against the
/// participant's `R_i` and the exact §4.2 context; a single invalid, missing,
/// duplicate, or misordered proof fails closed, so `C` is only formed once every
/// participant has proven knowledge of its share. `C = v*H + Σ R_i` is computed
/// by point addition; the scalar sum is never formed (§1.2). `R_total` and `C`
/// at infinity are rejected (§4.3) — the underlying point operations fail closed
/// on the identity.
pub fn aggregate_shared_commitment_v1(
    chain_id: &TrustedChainIdV1,
    session_id: [u8; 32],
    roster: &[[u8; 32]],
    value: u64,
    terms_hash: [u8; 32],
    capsule_hash: [u8; 32],
    contributions: &[BlindingShareV1],
) -> Result<SharedCommitmentV1> {
    if contributions.len() != roster.len() {
        return Err(AdaptorError::InvalidContext(
            "shared commitment requires one contribution per participant",
        ));
    }

    let mut share_points = Vec::with_capacity(contributions.len());
    for (expected_index, contribution) in contributions.iter().enumerate() {
        let expected_index = u16::try_from(expected_index).map_err(|_| {
            AdaptorError::InvalidContext("shared commitment participant index exceeds u16")
        })?;
        if contribution.participant_index != expected_index {
            return Err(AdaptorError::ParticipantOrder);
        }
        // §4.2: validate the proof of knowledge against the exact context before
        // the share is admitted into the aggregate.
        let statement = SharePoPStatementV1::new(
            chain_id,
            session_id,
            roster,
            contribution.role,
            contribution.participant_index,
            contribution.share_point.clone(),
            terms_hash,
            capsule_hash,
        )?;
        if !verify_share_knowledge_v1(&statement, &contribution.proof)? {
            return Err(AdaptorError::VerificationFailed(
                "share PoK does not verify against the participant R_i",
            ));
        }
        share_points.push(contribution.share_point.clone());
    }

    // §4.3: R_total = Σ R_i (point addition; rejects the identity).
    let r_total = scriptless_add_public_points(&share_points)?;
    let r_total_commitment = Commitment::from_compressed_bytes(&r_total.to_compressed_bytes())
        .map_err(|_| AdaptorError::InvalidContext("aggregate R_total is not a valid point"))?;

    // v*H, without forming any zero blinding: (v*H + b*G) - (b*G) = v*H, for a
    // nonzero b. commit rejects a zero blinding, so a fixed nonzero b is used.
    let base = BlindingFactor::from_bytes([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ])
    .map_err(|_| AdaptorError::InvalidContext("fixed value-generator blinding is invalid"))?;
    let value_plus_base = Commitment::commit(value, &base);
    let base_only = Commitment::commit(0, &base);
    let value_h = value_plus_base
        .sub(&base_only)
        .map_err(|_| AdaptorError::InvalidContext("value generator term is the identity"))?;

    // §4.3: C = v*H + R_total (rejects the identity).
    let commitment = value_h
        .add(&r_total_commitment)
        .map_err(|_| AdaptorError::InvalidContext("shared commitment is the identity"))?;

    Ok(SharedCommitmentV1 {
        commitment: *commitment.as_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::Hash256;

    fn chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_authenticated_genesis(0x0011_2233, &Hash256::from_bytes([0x11; 32]))
    }

    fn blinding(byte: u8) -> SigningShareV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = byte;
        SigningShareV1::from_be_bytes(bytes).expect("canonical blinding")
    }

    // A two-party roster ordered by participant id, with the matching blindings.
    fn two_party() -> (Vec<[u8; 32]>, [SigningShareV1; 2], [DirectionV1; 2]) {
        // The roster ids are opaque here; ordering is ascending by bytes.
        let roster = vec![[0x21u8; 32], [0x42u8; 32]];
        let blinds = [blinding(7), blinding(9)];
        let roles = [DirectionV1::Initiator, DirectionV1::Responder];
        (roster, blinds, roles)
    }

    fn contributions(
        chain: &TrustedChainIdV1,
        session: [u8; 32],
        roster: &[[u8; 32]],
        blinds: &[SigningShareV1; 2],
        roles: &[DirectionV1; 2],
        terms: [u8; 32],
        capsule: [u8; 32],
    ) -> Vec<BlindingShareV1> {
        (0..2)
            .map(|i| {
                contribute_blinding_share_v1(
                    chain, session, roster, roles[i], i as u16, &blinds[i], terms, capsule,
                )
                .expect("contribution")
            })
            .collect()
    }

    #[test]
    fn a_complete_valid_contribution_set_yields_a_commitment() {
        let (roster, blinds, roles) = two_party();
        let c = chain();
        let contribs = contributions(
            &c, [0x22; 32], &roster, &blinds, &roles, [0x33; 32], [0x44; 32],
        );
        let shared = aggregate_shared_commitment_v1(
            &c, [0x22; 32], &roster, 1_000, [0x33; 32], [0x44; 32], &contribs,
        )
        .expect("shared commitment");
        assert_ne!(shared.commitment_bytes(), &[0u8; 33]);
    }

    #[test]
    fn c_equals_value_h_plus_sum_of_shares() {
        // Independently reconstruct C = v*H + Σ R_i and compare. This confirms
        // the aggregate matches §4.3 without ever summing the scalars.
        let (roster, blinds, roles) = two_party();
        let c = chain();
        let contribs = contributions(
            &c, [0x22; 32], &roster, &blinds, &roles, [0x33; 32], [0x44; 32],
        );
        let shared = aggregate_shared_commitment_v1(
            &c, [0x22; 32], &roster, 1_000, [0x33; 32], [0x44; 32], &contribs,
        )
        .expect("shared");

        let r_total = scriptless_add_public_points(&[
            blinds[0].public_key().clone(),
            blinds[1].public_key().clone(),
        ])
        .expect("R_total");
        let r_total_c =
            Commitment::from_compressed_bytes(&r_total.to_compressed_bytes()).expect("R_total pt");
        let base = BlindingFactor::from_bytes({
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        })
        .expect("base");
        let value_h = Commitment::commit(1_000, &base)
            .sub(&Commitment::commit(0, &base))
            .expect("vH");
        let expected = value_h.add(&r_total_c).expect("C");
        assert_eq!(shared.commitment_bytes(), expected.as_bytes());
    }

    #[test]
    fn an_invalid_proof_fails_closed() {
        let (roster, blinds, roles) = two_party();
        let c = chain();
        let mut contribs = contributions(
            &c, [0x22; 32], &roster, &blinds, &roles, [0x33; 32], [0x44; 32],
        );
        // Swap participant 1's published share to a point it did not prove.
        contribs[1].share_point = blinding(13).public_key().clone();
        assert!(aggregate_shared_commitment_v1(
            &c, [0x22; 32], &roster, 1_000, [0x33; 32], [0x44; 32], &contribs,
        )
        .is_err());
    }

    #[test]
    fn a_missing_participant_fails_closed() {
        let (roster, blinds, roles) = two_party();
        let c = chain();
        let contribs = contributions(
            &c, [0x22; 32], &roster, &blinds, &roles, [0x33; 32], [0x44; 32],
        );
        assert!(aggregate_shared_commitment_v1(
            &c,
            [0x22; 32],
            &roster,
            1_000,
            [0x33; 32],
            [0x44; 32],
            &contribs[..1],
        )
        .is_err());
    }

    #[test]
    fn a_proof_bound_to_a_different_capsule_hash_fails_closed() {
        // §4.2 binds capsule_hash; a contribution proven under one capsule must
        // not aggregate under another.
        let (roster, blinds, roles) = two_party();
        let c = chain();
        let contribs = contributions(
            &c, [0x22; 32], &roster, &blinds, &roles, [0x33; 32], [0x44; 32],
        );
        assert!(aggregate_shared_commitment_v1(
            &c, [0x22; 32], &roster, 1_000, [0x33; 32], [0x55; 32], &contribs,
        )
        .is_err());
    }
}
