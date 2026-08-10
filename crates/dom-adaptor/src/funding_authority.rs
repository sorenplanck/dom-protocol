//! Funding authorization: bilateral backup and the inviolable refund-first order.
//!
//! Phase 4 of the implementation schedule, the parts that are pure logic. The
//! central security property is an order: money enters the contract only after
//! a guaranteed exit exists. Two conditions gate the funding signature.
//!
//! 1. **Bilateral backup.** The shared output's blinding sum is known to no
//!    single party and is irrecoverable from the chain (the C2 decision), so a
//!    party that loses its share material loses the funds with no recourse.
//!    Before any funding, each party must prove a backup roundtrip: export the
//!    share, reimport it, and confirm the reimported material reproduces the
//!    committed point `share*G`. Both acknowledgements must verify.
//!    `authorize` consumes the `BackupConfirmedV1` token, and that token can
//!    only be produced by `verify_bilateral_backup_v1` — so funding cannot be
//!    authorized without the backup gate having run and passed.
//!
//! 2. **Refund-first order.** The refund spending the shared output must be
//!    co-signed, with the height-locked kernel at `H_refund`, before the
//!    funding is signed. This module consumes evidence that the contract stage
//!    is `RefundPresigned`; it cannot mint funding authority from an earlier
//!    stage.
//!
//! Scope and known gaps (this is the pure-logic typestate half, not the full
//! §7.3 `ReadyToFund` gate):
//!
//! - The backup token records only that a matching ack set verified against the
//!   `committed_share_points` the caller supplied. It is **not** cryptographically
//!   bound to this contract's shared-output shares — the caller must pass the
//!   session's real committed points. Binding the backup receipt to the frozen
//!   shared output (the spec's `FundingGateEvidence.backup_receipt` over
//!   `terms_hash`/`shared_output_hash`) is node-side integration.
//! - The master spec §7.2/§7.3 also requires the claim adaptor pre-signature to
//!   be built and verified, and `ReadyToFund` persisted, before funding is
//!   authorized (the gate transitions from `Phase::ClaimPrepared`). The
//!   implementation schedule orders funding (Phase 4) before the conditional
//!   claim (Phase 5); this ordering divergence is recorded for adjudication in
//!   the scriptless findings record and is not resolved here.
//! - Building and broadcasting the actual funding and refund transactions, and
//!   the escalating-fee refund ladder under a real relay, are node-side work.
//!
//! This module authorizes the ordering; it does not sign or broadcast.

use crate::{AdaptorError, ContractStageV1, ContractStateV1, Result};
use dom_crypto::PublicKey;

/// One party's acknowledgement that its share survived a backup roundtrip.
///
/// The party exported its share material, reimported it, and derived the
/// point from the reimported bytes. The ack carries the participant index and
/// that recovered point; the gate checks it against the committed share point.
/// The ack proves the roundtrip succeeded without carrying any secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareBackupAckV1 {
    participant_index: u16,
    recovered_share_point: PublicKey,
}

impl ShareBackupAckV1 {
    /// Record a backup acknowledgement for one participant.
    pub const fn new(participant_index: u16, recovered_share_point: PublicKey) -> Self {
        Self {
            participant_index,
            recovered_share_point,
        }
    }

    /// The participant this acknowledgement belongs to.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }
}

/// Proof that every participant confirmed a valid backup roundtrip.
///
/// This token exists only when the bilateral backup gate passed: its only
/// constructor is `verify_bilateral_backup_v1`, so a caller cannot fabricate
/// one without a complete, matching ack set. It is a witness that the gate ran,
/// consumed by `FundingAuthorizationV1::authorize`. It records the participant
/// count only; binding the backed-up shares to a specific contract's shared
/// output is the caller's responsibility (see the module scope note).
#[derive(Debug, Clone, Copy)]
pub struct BackupConfirmedV1 {
    participant_count: usize,
}

impl BackupConfirmedV1 {
    /// The number of participants whose backup was confirmed.
    pub const fn participant_count(&self) -> usize {
        self.participant_count
    }
}

/// Require a verified backup acknowledgement from every participant.
///
/// `committed_share_points` are the share points the session agreed on, in
/// participant order. Each participant must supply exactly one ack whose
/// recovered point equals its committed point. Missing, duplicate,
/// out-of-range, or mismatched acks all fail closed, so funding cannot proceed
/// on a partial or forged backup set.
pub fn verify_bilateral_backup_v1(
    committed_share_points: &[PublicKey],
    acks: &[ShareBackupAckV1],
) -> Result<BackupConfirmedV1> {
    let participant_count = committed_share_points.len();
    if participant_count < 2 {
        return Err(AdaptorError::InvalidContext(
            "bilateral backup requires at least two participants",
        ));
    }
    let mut seen = vec![false; participant_count];
    for ack in acks {
        let position = usize::from(ack.participant_index);
        if position >= participant_count {
            return Err(AdaptorError::InvalidContext(
                "backup acknowledgement index is outside the roster",
            ));
        }
        if seen[position] {
            return Err(AdaptorError::DuplicateParticipant);
        }
        if ack.recovered_share_point != committed_share_points[position] {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        seen[position] = true;
    }
    if !seen.iter().all(|confirmed| *confirmed) {
        return Err(AdaptorError::InvalidContext(
            "bilateral backup is missing a participant acknowledgement",
        ));
    }
    Ok(BackupConfirmedV1 { participant_count })
}

/// Authority to sign the funding, minted only after the two conditions hold.
///
/// Construction consumes the backup-confirmed token and the contract state,
/// and requires the state to be exactly at `RefundPresigned`. There is no
/// other constructor, so a caller cannot assemble funding authority before the
/// refund exists or before every backup was confirmed. The type is one-shot:
/// it is consumed to advance the contract to `Funded`.
#[derive(Debug)]
pub struct FundingAuthorizationV1 {
    session_transcript: [u8; 32],
}

impl FundingAuthorizationV1 {
    /// Authorize funding once the refund is presigned and backups confirmed.
    ///
    /// The state must be at `RefundPresigned`: authorizing funding from
    /// `Proposed` or `SharedOutputBuilt` would mean money could enter before
    /// the exit exists, and from `Funded` or a terminal it would be a replay.
    /// Consuming `backup` requires the caller to have passed the bilateral
    /// backup gate; a token for fewer than two participants is rejected, since a
    /// 2-of-2 contract cannot be safely funded without both parties' backups.
    pub fn authorize(state: &ContractStateV1, backup: BackupConfirmedV1) -> Result<Self> {
        if state.stage() != ContractStageV1::RefundPresigned {
            return Err(AdaptorError::InvalidContext(
                "funding may be authorized only from the RefundPresigned stage",
            ));
        }
        if backup.participant_count() < 2 {
            return Err(AdaptorError::InvalidContext(
                "funding requires a bilateral backup for at least two participants",
            ));
        }
        Ok(Self {
            session_transcript: state.transcript(),
        })
    }

    /// The transcript the funding authority is bound to, for cross-checking
    /// against the envelope that drives the `Funded` transition.
    pub const fn bound_transcript(&self) -> &[u8; 32] {
        &self.session_transcript
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContractEnvelopeV1, ContractKindV1, DirectionV1, SigningShareV1, TrustedChainIdV1,
    };

    fn point(value: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes)
            .expect("fixture scalar")
            .public_key()
            .clone()
    }

    fn chain() -> TrustedChainIdV1 {
        TrustedChainIdV1::from_signed_fixture([0x11; 32])
    }

    fn committed() -> Vec<PublicKey> {
        vec![point(3), point(5)]
    }

    #[test]
    fn a_complete_matching_backup_set_passes() {
        let points = committed();
        let acks = vec![
            ShareBackupAckV1::new(0, points[0].clone()),
            ShareBackupAckV1::new(1, points[1].clone()),
        ];
        let confirmed = verify_bilateral_backup_v1(&points, &acks).expect("backup");
        assert_eq!(confirmed.participant_count(), 2);
    }

    #[test]
    fn a_missing_participant_fails_closed() {
        let points = committed();
        let acks = vec![ShareBackupAckV1::new(0, points[0].clone())];
        assert!(verify_bilateral_backup_v1(&points, &acks).is_err());
    }

    #[test]
    fn a_wrong_recovered_point_fails_closed() {
        let points = committed();
        let acks = vec![
            ShareBackupAckV1::new(0, points[0].clone()),
            // Party 1 recovered the wrong point: its backup did not roundtrip.
            ShareBackupAckV1::new(1, point(9)),
        ];
        assert!(matches!(
            verify_bilateral_backup_v1(&points, &acks),
            Err(AdaptorError::AuthorizationMismatch)
        ));
    }

    #[test]
    fn a_duplicated_participant_cannot_cover_for_the_other() {
        let points = committed();
        let acks = vec![
            ShareBackupAckV1::new(0, points[0].clone()),
            ShareBackupAckV1::new(0, points[0].clone()),
        ];
        assert!(matches!(
            verify_bilateral_backup_v1(&points, &acks),
            Err(AdaptorError::DuplicateParticipant)
        ));
    }

    fn state_at_refund_presigned() -> ContractStateV1 {
        let mut state = ContractStateV1::open([0x33; 32]).expect("open");
        let steps = [
            (
                DirectionV1::Initiator,
                ContractStageV1::SharedOutputBuilt,
                0u64,
            ),
            (
                DirectionV1::Responder,
                ContractStageV1::RefundPresigned,
                0u64,
            ),
        ];
        for (sender, target, seq) in steps {
            let env = ContractEnvelopeV1::new(
                &chain(),
                [0x22; 32],
                sender,
                ContractKindV1::WitnessOrTimeout,
                seq,
                target,
                state.transcript(),
                vec![0xAB; 4],
            )
            .expect("envelope");
            state.apply(&env).expect("transition");
        }
        state
    }

    #[test]
    fn funding_authorizes_only_from_refund_presigned() {
        let points = committed();
        let acks = vec![
            ShareBackupAckV1::new(0, points[0].clone()),
            ShareBackupAckV1::new(1, points[1].clone()),
        ];

        // From RefundPresigned with confirmed backups, authorization succeeds.
        let state = state_at_refund_presigned();
        let backup = verify_bilateral_backup_v1(&points, &acks).expect("backup");
        let authority = FundingAuthorizationV1::authorize(&state, backup).expect("authorize");
        assert_eq!(authority.bound_transcript(), &state.transcript());

        // From the earlier SharedOutputBuilt stage, it must fail: money would
        // enter before the refund exists.
        let mut early = ContractStateV1::open([0x33; 32]).expect("open");
        let env = ContractEnvelopeV1::new(
            &chain(),
            [0x22; 32],
            DirectionV1::Initiator,
            ContractKindV1::WitnessOrTimeout,
            0,
            ContractStageV1::SharedOutputBuilt,
            early.transcript(),
            vec![0xAB; 4],
        )
        .expect("envelope");
        early.apply(&env).expect("transition");
        let backup2 = verify_bilateral_backup_v1(&points, &acks).expect("backup");
        assert!(FundingAuthorizationV1::authorize(&early, backup2).is_err());
    }
}
