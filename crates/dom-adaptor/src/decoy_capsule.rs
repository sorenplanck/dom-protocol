//! Deterministic canonical decoy capsule for the shared-output profile.
//!
//! A shared output's blinding sum is known to no single party, so no real
//! recovery capsule can exist for it. The output must still carry a capsule
//! that is byte-shape indistinguishable from a real one: version `01 00`,
//! twelve nonce bytes, ciphertext length `50 00`, and an eighty-byte body.
//!
//! The ninety-two variable bytes are fixed by bilateral commit–reveal. Each
//! party's contribution is derived deterministically from its long-term
//! signing share and the session identifier, so aborting and restarting the
//! same session reproduces the same bytes — re-rolling across restarts would
//! otherwise open a grinding channel on the capsule. Commit-before-reveal
//! stops either party from choosing its contribution after seeing the
//! other's; the combined bytes are pseudorandom if either party is honest.

use crate::{AdaptorError, Result, SessionId, SigningShareV1};
use dom_crypto::blake2b_256_tagged;
use dom_crypto::recovery::{
    RecoveryCapsule, RECOVERY_CAPSULE_SIZE, RECOVERY_CIPHERTEXT_SIZE, RECOVERY_NONCE_SIZE,
    RECOVERY_VERSION,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const CONTRIBUTION_TAG_V1: &str = "DOM:scriptless-decoy-contribution:v1";
const COMMIT_TAG_V1: &str = "DOM:scriptless-decoy-commit:v1";

// Framing offsets of the real recovery capsule, derived from the DOM capsule
// constants so the decoy cannot silently diverge from the real layout if those
// constants ever change (Cronograma A.2: the sizes must be imported from the
// DOM module, not duplicated). Layout: version || nonce || ct-len || body.
const CAPSULE_VERSION_LEN: usize = 2;
const CAPSULE_LENGTH_FIELD_LEN: usize = 2;
const CAPSULE_NONCE_OFFSET: usize = CAPSULE_VERSION_LEN;
const CAPSULE_LENGTH_OFFSET: usize = CAPSULE_NONCE_OFFSET + RECOVERY_NONCE_SIZE;
const CAPSULE_BODY_OFFSET: usize = CAPSULE_LENGTH_OFFSET + CAPSULE_LENGTH_FIELD_LEN;

/// Variable bytes fixed by the bilateral exchange: nonce plus body.
pub const DECOY_VARIABLE_LEN: usize = RECOVERY_NONCE_SIZE + RECOVERY_CIPHERTEXT_SIZE;

/// One party's ninety-two-byte decoy contribution.
///
/// The value must stay private until the counterparty's commitment arrives;
/// the type therefore implements no clone, copy, debug, display, equality, or
/// generic serialization, and its bytes are zeroized on drop.
pub struct DecoyContributionV1 {
    bytes: Zeroizing<[u8; DECOY_VARIABLE_LEN]>,
}

impl DecoyContributionV1 {
    /// Derive this session's contribution from the long-term signing share.
    ///
    /// Determinism is the anti-grinding property: the same share and session
    /// always produce the same bytes, so a party cannot obtain a fresh draw by
    /// aborting and restarting the session.
    pub fn derive(share: &SigningShareV1, session_id: &SessionId) -> Self {
        // The seed folds in the private share, so the stream is unpredictable
        // to anyone without it, and is bound to the session, so a restart
        // reproduces it rather than drawing anew.
        let keyed = share.decoy_seed_v1(session_id.as_bytes());
        let mut bytes = Zeroizing::new([0u8; DECOY_VARIABLE_LEN]);
        let first = blake2b_256_tagged(CONTRIBUTION_TAG_V1, keyed.as_slice());
        let second = blake2b_256_tagged(CONTRIBUTION_TAG_V1, first.as_bytes());
        let third = blake2b_256_tagged(CONTRIBUTION_TAG_V1, second.as_bytes());
        bytes[..32].copy_from_slice(first.as_bytes());
        bytes[32..64].copy_from_slice(second.as_bytes());
        bytes[64..].copy_from_slice(&third.as_bytes()[..28]);
        Self { bytes }
    }

    /// Return the binding commitment to exchange before any reveal.
    pub fn commitment(&self) -> DecoyCommitmentV1 {
        DecoyCommitmentV1(*blake2b_256_tagged(COMMIT_TAG_V1, self.bytes.as_slice()).as_bytes())
    }

    /// Consume the contribution into its reveal bytes.
    ///
    /// Call only after the counterparty's commitment has been received and
    /// durably recorded; revealing first surrenders the commit–reveal order.
    pub fn into_reveal(self) -> DecoyRevealV1 {
        DecoyRevealV1 { bytes: self.bytes }
    }
}

/// A thirty-two-byte binding commitment to one decoy contribution.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DecoyCommitmentV1([u8; 32]);

impl DecoyCommitmentV1 {
    /// Parse exchanged commitment bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Serialize for the exchange.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// A revealed ninety-two-byte contribution.
pub struct DecoyRevealV1 {
    bytes: Zeroizing<[u8; DECOY_VARIABLE_LEN]>,
}

impl DecoyRevealV1 {
    /// Parse the counterparty's reveal bytes.
    pub fn from_bytes(bytes: [u8; DECOY_VARIABLE_LEN]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Serialize for the exchange.
    pub fn to_bytes(&self) -> [u8; DECOY_VARIABLE_LEN] {
        *self.bytes
    }
}

/// Combine both reveals into the canonical ninety-six-byte decoy capsule.
///
/// The remote reveal must match the commitment received before the local
/// reveal was sent; a mismatch is an equivocation and fails closed. The two
/// contributions are combined by XOR, so the result is outside either party's
/// unilateral control, and the capsule is framed exactly as a real recovery
/// capsule: `01 00 || nonce[12] || 50 00 || body[80]`.
pub fn combine_decoy_capsule_v1(
    local: &DecoyRevealV1,
    remote: &DecoyRevealV1,
    remote_commitment: &DecoyCommitmentV1,
) -> Result<RecoveryCapsule> {
    let recomputed = blake2b_256_tagged(COMMIT_TAG_V1, remote.bytes.as_slice());
    if recomputed
        .as_bytes()
        .ct_eq(&remote_commitment.0)
        .unwrap_u8()
        != 1
    {
        return Err(AdaptorError::InvalidContext(
            "decoy reveal does not match the committed contribution",
        ));
    }
    if local.bytes.ct_eq(remote.bytes.as_slice()).unwrap_u8() == 1 {
        return Err(AdaptorError::InvalidContext(
            "decoy contributions must be distinct",
        ));
    }

    let mut combined = Zeroizing::new([0u8; DECOY_VARIABLE_LEN]);
    for (out, (a, b)) in combined
        .iter_mut()
        .zip(local.bytes.iter().zip(remote.bytes.iter()))
    {
        *out = a ^ b;
    }

    let mut capsule = [0u8; RECOVERY_CAPSULE_SIZE];
    capsule[..CAPSULE_NONCE_OFFSET].copy_from_slice(&RECOVERY_VERSION.to_le_bytes());
    capsule[CAPSULE_NONCE_OFFSET..CAPSULE_LENGTH_OFFSET]
        .copy_from_slice(&combined[..RECOVERY_NONCE_SIZE]);
    capsule[CAPSULE_LENGTH_OFFSET..CAPSULE_BODY_OFFSET]
        .copy_from_slice(&(RECOVERY_CIPHERTEXT_SIZE as u16).to_le_bytes());
    capsule[CAPSULE_BODY_OFFSET..].copy_from_slice(&combined[RECOVERY_NONCE_SIZE..]);
    RecoveryCapsule::from_bytes(&capsule)
        .map_err(|_| AdaptorError::InvalidContext("combined decoy failed capsule framing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(byte: u8) -> SigningShareV1 {
        SigningShareV1::from_be_bytes([byte; 32]).expect("test share")
    }

    fn session(byte: u8) -> SessionId {
        SessionId::from_bytes([byte; 32]).expect("test session")
    }

    fn capsule_for(a: u8, b: u8, sid: u8) -> RecoveryCapsule {
        let local = DecoyContributionV1::derive(&share(a), &session(sid));
        let remote = DecoyContributionV1::derive(&share(b), &session(sid));
        let remote_commit = remote.commitment();
        combine_decoy_capsule_v1(&local.into_reveal(), &remote.into_reveal(), &remote_commit)
            .expect("combine")
    }

    #[test]
    fn framing_matches_the_real_capsule_exactly() {
        let capsule = capsule_for(3, 5, 9);
        let bytes = capsule.as_bytes();
        assert_eq!(bytes.len(), RECOVERY_CAPSULE_SIZE);
        assert_eq!(&bytes[..2], &[0x01, 0x00]);
        assert_eq!(&bytes[14..16], &[0x50, 0x00]);
        assert!(RecoveryCapsule::from_bytes(bytes).is_ok());
    }

    #[test]
    fn both_parties_compute_the_identical_capsule() {
        let a = DecoyContributionV1::derive(&share(3), &session(9));
        let b = DecoyContributionV1::derive(&share(5), &session(9));
        let commit_a = a.commitment();
        let commit_b = b.commitment();
        let side_a = combine_decoy_capsule_v1(
            &DecoyContributionV1::derive(&share(3), &session(9)).into_reveal(),
            &b.into_reveal(),
            &commit_b,
        )
        .expect("side A");
        let side_b = combine_decoy_capsule_v1(
            &DecoyContributionV1::derive(&share(5), &session(9)).into_reveal(),
            &a.into_reveal(),
            &commit_a,
        )
        .expect("side B");
        assert_eq!(side_a.as_bytes(), side_b.as_bytes());
    }

    #[test]
    fn restart_of_the_same_session_reproduces_the_same_bytes() {
        assert_eq!(
            capsule_for(3, 5, 9).as_bytes(),
            capsule_for(3, 5, 9).as_bytes(),
            "abort-and-restart must not grant a fresh draw"
        );
    }

    #[test]
    fn different_sessions_and_shares_change_the_capsule() {
        let base = capsule_for(3, 5, 9);
        assert_ne!(base.as_bytes(), capsule_for(3, 5, 10).as_bytes());
        assert_ne!(base.as_bytes(), capsule_for(4, 5, 9).as_bytes());
    }

    #[test]
    fn equivocating_reveal_fails_closed() {
        let local = DecoyContributionV1::derive(&share(3), &session(9));
        let remote = DecoyContributionV1::derive(&share(5), &session(9));
        let honest_commit = remote.commitment();
        let substituted = DecoyContributionV1::derive(&share(6), &session(9));
        assert!(combine_decoy_capsule_v1(
            &local.into_reveal(),
            &substituted.into_reveal(),
            &honest_commit,
        )
        .is_err());
    }

    #[test]
    fn identical_contributions_are_rejected() {
        let local = DecoyContributionV1::derive(&share(3), &session(9));
        let mirror = DecoyContributionV1::derive(&share(3), &session(9));
        let commit = mirror.commitment();
        assert!(
            combine_decoy_capsule_v1(&local.into_reveal(), &mirror.into_reveal(), &commit).is_err(),
            "a mirrored contribution would zero the combined bytes"
        );
    }
}
