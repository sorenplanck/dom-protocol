//! Canonical share proof-of-knowledge V1.

use crate::{
    error::exact_array, AdaptorError, DirectionV1, Result, SigningShareV1, TrustedChainIdV1,
};
use dom_crypto::{
    blake2b_256_tagged, scalar_bytes_are_canonical, scalar_from_wide_be,
    secret_scalar_mul_add_assign, secret_scalar_public_key, verify_scalar_response, PublicKey,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const CONTEXT_TAG_V1: &str = "DOM:scriptless-share-pop:v1";
const CHALLENGE_TAG_V1: &str = "DOM:scriptless-share-pop-challenge:v1";
const MAGIC: &[u8; 4] = b"DSPO";
const VERSION: u16 = 1;
const MIN_PARTICIPANTS: usize = 2;
const MAX_PARTICIPANTS: usize = 16;

/// Exact 202-byte statement for proving knowledge of one signing share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharePoPStatementV1 {
    bytes: [u8; Self::ENCODED_LEN],
    share_point: PublicKey,
    role: DirectionV1,
}

impl SharePoPStatementV1 {
    /// Canonical statement length.
    pub const ENCODED_LEN: usize = 202;

    /// Construct and validate a statement against the authenticated roster.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: &TrustedChainIdV1,
        session_id: [u8; 32],
        participant_roster: &[[u8; 32]],
        role: DirectionV1,
        participant_index: u16,
        share_point: PublicKey,
        terms_hash: [u8; 32],
        recovery_binding_hash: [u8; 32],
    ) -> Result<Self> {
        validate_roster(participant_roster, participant_index)?;
        if chain_id.as_bytes() == &[0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "share PoK chain ID must be nonzero",
            ));
        }
        if session_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "share PoK session ID must be nonzero",
            ));
        }
        if terms_hash == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "share PoK terms hash must be nonzero",
            ));
        }
        if recovery_binding_hash == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "share PoK recovery binding hash must be nonzero",
            ));
        }
        let participant_id = participant_roster[usize::from(participant_index)];
        if participant_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "share PoK participant ID must be nonzero",
            ));
        }
        let share_bytes = share_point.to_compressed_bytes();
        if PublicKey::from_compressed_bytes(&share_bytes)?.to_compressed_bytes() != share_bytes {
            return Err(AdaptorError::InvalidContext(
                "share PoK point must re-encode canonically",
            ));
        }

        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[6..38].copy_from_slice(chain_id.as_bytes());
        bytes[38..70].copy_from_slice(&session_id);
        bytes[70..102].copy_from_slice(&participant_id);
        bytes[102] = role.to_byte();
        bytes[103..105].copy_from_slice(&participant_index.to_le_bytes());
        bytes[105..138].copy_from_slice(&share_bytes);
        bytes[138..170].copy_from_slice(&terms_hash);
        bytes[170..202].copy_from_slice(&recovery_binding_hash);
        Ok(Self {
            bytes,
            share_point,
            role,
        })
    }

    /// Parse exact statement bytes and bind them to the authenticated roster.
    pub fn from_bytes(
        bytes: &[u8],
        trusted_chain_id: &TrustedChainIdV1,
        participant_roster: &[[u8; 32]],
    ) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("SharePoPStatementV1", bytes)?;
        if &bytes[..4] != MAGIC {
            return Err(AdaptorError::InvalidContext("share PoK magic mismatch"));
        }
        if u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION {
            return Err(AdaptorError::InvalidContext(
                "share PoK version must be exactly V1",
            ));
        }
        let participant_index = u16::from_le_bytes([bytes[103], bytes[104]]);
        validate_roster(participant_roster, participant_index)?;
        let expected_participant = participant_roster[usize::from(participant_index)];
        if bytes[70..102] != expected_participant {
            return Err(AdaptorError::InvalidContext(
                "share PoK participant does not match roster index",
            ));
        }
        if bytes[6..38] != *trusted_chain_id.as_bytes() {
            return Err(AdaptorError::InvalidContext(
                "share PoK chain ID differs from the trusted local chain",
            ));
        }
        if bytes[38..70] == [0u8; 32]
            || bytes[70..102] == [0u8; 32]
            || bytes[138..170] == [0u8; 32]
            || bytes[170..202] == [0u8; 32]
        {
            return Err(AdaptorError::InvalidContext(
                "share PoK fixed digest fields must be nonzero",
            ));
        }
        let role = DirectionV1::try_from(bytes[102])?;
        let share_bytes = exact_array::<33>("SharePoPStatementV1 share point", &bytes[105..138])?;
        let share_point = PublicKey::from_compressed_bytes(&share_bytes)?;
        if share_point.to_compressed_bytes() != share_bytes {
            return Err(AdaptorError::InvalidContext(
                "share PoK point must re-encode canonically",
            ));
        }
        Ok(Self {
            bytes,
            share_point,
            role,
        })
    }

    /// Return the exact canonical statement bytes.
    pub const fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.bytes
    }

    /// Return the participant share point.
    pub fn share_point(&self) -> PublicKey {
        self.share_point.clone()
    }

    /// Return the stable participant role.
    pub fn role(&self) -> DirectionV1 {
        self.role
    }

    /// Return the authenticated participant index.
    pub fn participant_index(&self) -> u16 {
        u16::from_le_bytes([self.bytes[103], self.bytes[104]])
    }

    fn context_digest(&self) -> [u8; 32] {
        *blake2b_256_tagged(CONTEXT_TAG_V1, &self.bytes).as_bytes()
    }
}

/// Exact 65-byte Schnorr proof of knowledge for a signing share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareProofV1 {
    commitment: PublicKey,
    response: [u8; 32],
}

impl ShareProofV1 {
    /// Canonical proof length.
    pub const ENCODED_LEN: usize = 65;

    /// Parse an exact proof and reject noncanonical points or response scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("ShareProofV1", bytes)?;
        let commitment_bytes = exact_array::<33>("ShareProofV1 commitment", &bytes[..33])?;
        let commitment = PublicKey::from_compressed_bytes(&commitment_bytes)?;
        if commitment.to_compressed_bytes() != commitment_bytes {
            return Err(AdaptorError::InvalidContext(
                "share PoK commitment must re-encode canonically",
            ));
        }
        let response = exact_array::<32>("ShareProofV1 response", &bytes[33..])?;
        if !scalar_bytes_are_canonical(&response, true) {
            return Err(AdaptorError::InvalidContext(
                "share PoK response is a noncanonical scalar",
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

/// Generate a fresh proof with the authoritative operating-system CSPRNG.
pub fn prove_share_knowledge_v1(
    statement: &SharePoPStatementV1,
    signing_share: &SigningShareV1,
) -> Result<ShareProofV1> {
    if signing_share.public_key() != &statement.share_point() {
        return Err(AdaptorError::AuthorizationMismatch);
    }
    let nonce = random_secret_scalar()?;
    prove_with_nonce(statement, signing_share, nonce)
}

/// Verify the exact V1 share proof relation.
pub fn verify_share_knowledge_v1(
    statement: &SharePoPStatementV1,
    proof: &ShareProofV1,
) -> Result<bool> {
    let challenge = challenge_scalar(statement, proof.commitment())?;
    verify_scalar_response(
        proof.response(),
        proof.commitment(),
        &challenge,
        &statement.share_point(),
    )
    .map_err(Into::into)
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
    statement: &SharePoPStatementV1,
    signing_share: &SigningShareV1,
    mut nonce: Zeroizing<[u8; 32]>,
) -> Result<ShareProofV1> {
    let commitment = secret_scalar_public_key(&nonce)?;
    let challenge = challenge_scalar(statement, &commitment)?;
    secret_scalar_mul_add_assign(&mut nonce, signing_share.as_be_bytes(), &challenge)?;
    ShareProofV1::from_bytes(&{
        let mut bytes = [0u8; ShareProofV1::ENCODED_LEN];
        bytes[..33].copy_from_slice(&commitment.to_compressed_bytes());
        bytes[33..].copy_from_slice(nonce.as_ref());
        bytes
    })
}

fn challenge_scalar(
    statement: &SharePoPStatementV1,
    commitment: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut challenge_input = Zeroizing::new([0u8; 102]);
    challenge_input[..32].copy_from_slice(&statement.context_digest());
    challenge_input[32..65].copy_from_slice(&statement.share_point().to_compressed_bytes());
    challenge_input[65..98].copy_from_slice(&commitment.to_compressed_bytes());

    let mut counter = 0u32;
    loop {
        challenge_input[98..].copy_from_slice(&counter.to_le_bytes());
        let mut first_input = Zeroizing::new([0u8; 103]);
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

fn validate_roster(participant_roster: &[[u8; 32]], participant_index: u16) -> Result<()> {
    if !(MIN_PARTICIPANTS..=MAX_PARTICIPANTS).contains(&participant_roster.len()) {
        return Err(AdaptorError::InvalidContext(
            "share PoK roster must contain 2 through 16 participants",
        ));
    }
    if usize::from(participant_index) >= participant_roster.len() {
        return Err(AdaptorError::InvalidContext(
            "share PoK participant index is outside the roster",
        ));
    }
    for (index, participant) in participant_roster.iter().enumerate() {
        if participant == &[0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "share PoK roster contains a zero participant ID",
            ));
        }
        if participant_roster[index + 1..].contains(participant) {
            return Err(AdaptorError::DuplicateParticipant);
        }
    }
    if participant_roster.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(AdaptorError::ParticipantOrder);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: u8) -> SigningShareV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes).expect("small scalar is canonical")
    }

    fn nonce(value: u8) -> Zeroizing<[u8; 32]> {
        scalar(value).zeroizing_bytes()
    }

    fn fixture() -> (SharePoPStatementV1, Vec<[u8; 32]>, SigningShareV1) {
        let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        let roster = vec![[0x21; 32], [0x42; 32]];
        let share = scalar(7);
        let statement = SharePoPStatementV1::new(
            &chain,
            [0x22; 32],
            &roster,
            DirectionV1::Initiator,
            0,
            share.public_key().clone(),
            [0x33; 32],
            [0x44; 32],
        )
        .expect("fixture statement");
        (statement, roster, share)
    }

    #[test]
    fn deterministic_proof_roundtrips_and_mutations_fail() {
        let (statement, roster, share) = fixture();
        let proof = prove_with_nonce(&statement, &share, nonce(9)).expect("proof");
        assert!(verify_share_knowledge_v1(&statement, &proof).expect("verification"));
        assert_eq!(
            SharePoPStatementV1::from_bytes(
                &statement.to_bytes(),
                &TrustedChainIdV1::from_signed_fixture([0x11; 32]),
                &roster,
            )
            .expect("statement roundtrip"),
            statement
        );
        assert_eq!(
            ShareProofV1::from_bytes(&proof.to_bytes()).expect("proof roundtrip"),
            proof
        );

        for index in 0..ShareProofV1::ENCODED_LEN {
            let mut mutated = proof.to_bytes();
            mutated[index] ^= 1;
            if let Ok(parsed) = ShareProofV1::from_bytes(&mutated) {
                assert!(
                    !verify_share_knowledge_v1(&statement, &parsed).expect("negative verify"),
                    "proof mutation {index} verified"
                );
            }
        }

        for index in 0..SharePoPStatementV1::ENCODED_LEN {
            let mut mutated = statement.to_bytes();
            mutated[index] ^= 1;
            if let Ok(parsed) = SharePoPStatementV1::from_bytes(
                &mutated,
                &TrustedChainIdV1::from_signed_fixture([0x11; 32]),
                &roster,
            ) {
                assert!(
                    !verify_share_knowledge_v1(&parsed, &proof).expect("negative verify"),
                    "statement mutation {index} verified"
                );
            }
        }
    }

    #[test]
    fn parser_rejects_wrong_lengths_roster_and_scalar_order() {
        let (statement, roster, _) = fixture();
        let trusted = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        assert!(
            SharePoPStatementV1::from_bytes(&statement.to_bytes()[..201], &trusted, &roster)
                .is_err()
        );
        let mut duplicate = roster.clone();
        duplicate[1] = duplicate[0];
        assert!(
            SharePoPStatementV1::from_bytes(&statement.to_bytes(), &trusted, &duplicate).is_err()
        );

        let mut proof = [0u8; ShareProofV1::ENCODED_LEN];
        proof[..33].copy_from_slice(&scalar(3).public_key().to_compressed_bytes());
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        proof[33..].copy_from_slice(&ORDER);
        assert!(ShareProofV1::from_bytes(&proof).is_err());
        proof[33..].fill(0);
        assert!(ShareProofV1::from_bytes(&proof).is_ok());
    }

    #[test]
    fn wrong_share_cannot_prove_statement() {
        let (statement, _, _) = fixture();
        assert!(matches!(
            prove_share_knowledge_v1(&statement, &scalar(8)),
            Err(AdaptorError::AuthorizationMismatch)
        ));
    }

    #[test]
    fn role_index_terms_and_recovery_are_bound() {
        let (statement, roster, share) = fixture();
        let proof = prove_with_nonce(&statement, &share, nonce(9)).expect("proof");
        let chain = TrustedChainIdV1::from_signed_fixture([0x11; 32]);
        let variants = [
            SharePoPStatementV1::new(
                &chain,
                [0x22; 32],
                &roster,
                DirectionV1::Responder,
                0,
                share.public_key().clone(),
                [0x33; 32],
                [0x44; 32],
            )
            .expect("role variant"),
            SharePoPStatementV1::new(
                &chain,
                [0x22; 32],
                &roster,
                DirectionV1::Initiator,
                1,
                share.public_key().clone(),
                [0x33; 32],
                [0x44; 32],
            )
            .expect("index variant"),
            SharePoPStatementV1::new(
                &chain,
                [0x22; 32],
                &roster,
                DirectionV1::Initiator,
                0,
                share.public_key().clone(),
                [0x34; 32],
                [0x44; 32],
            )
            .expect("terms variant"),
            SharePoPStatementV1::new(
                &chain,
                [0x22; 32],
                &roster,
                DirectionV1::Initiator,
                0,
                share.public_key().clone(),
                [0x33; 32],
                [0x45; 32],
            )
            .expect("recovery variant"),
        ];
        for variant in variants {
            assert!(!verify_share_knowledge_v1(&variant, &proof).expect("negative verify"));
        }
    }
}
