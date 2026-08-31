//! Canonical payloads for the prepared DSC1 terms and share-PoK boundary.
//!
//! These codecs deliberately do not encode economic terms. `Offer` and
//! `Accept` carry only a commitment issued by the retained Contracts
//! authority after it has authenticated the session terms, chain, roster,
//! recovery binding, and expected public share points. `ShareCommit` commits
//! to the exact canonical `ShareReveal` bytes, and the reveal wraps the live
//! [`SharePoPStatementV1`] and [`ShareProofV1`] primitives without defining a
//! second proof format.

use crate::{
    error::exact_array, verify_share_knowledge_v1, AdaptorError, Result, SharePoPStatementV1,
    ShareProofV1, TrustedChainIdV1,
};
use dom_crypto::blake2b_256;

const TERMS_MAGIC: &[u8; 8] = b"DOMSETM1";
const SHARE_COMMIT_MAGIC: &[u8; 8] = b"DOMSSCM1";
const SHARE_REVEAL_MAGIC: &[u8; 8] = b"DOMSSRV1";
const VERSION: u16 = 1;

/// Closed kind carried by the fixed-size early terms acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EarlyTermsMessageKindV1 {
    /// The initiator's initial offer of an already-authenticated context.
    Offer = 0x01,
    /// The responder's acceptance of exactly that context.
    Accept = 0x02,
}

impl TryFrom<u8> for EarlyTermsMessageKindV1 {
    type Error = AdaptorError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Offer),
            0x02 => Ok(Self::Accept),
            _ => Err(AdaptorError::InvalidContext(
                "unknown early terms message kind",
            )),
        }
    }
}

/// Exact acknowledgement of one Store-authenticated early-session context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyTermsBindingV1 {
    bytes: [u8; Self::ENCODED_LEN],
    kind: EarlyTermsMessageKindV1,
    context_commitment: [u8; 32],
}

impl EarlyTermsBindingV1 {
    /// Exact canonical length.
    pub const ENCODED_LEN: usize = 44;

    /// Construct an offer or acceptance for a nonzero prepared commitment.
    pub fn new(kind: EarlyTermsMessageKindV1, context_commitment: [u8; 32]) -> Result<Self> {
        if context_commitment == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "early terms context commitment must be nonzero",
            ));
        }
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[..8].copy_from_slice(TERMS_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10] = kind as u8;
        bytes[12..].copy_from_slice(&context_commitment);
        Ok(Self {
            bytes,
            kind,
            context_commitment,
        })
    }

    /// Parse the exact V1 encoding and reject trailing or reserved bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("EarlyTermsBindingV1", bytes)?;
        if &bytes[..8] != TERMS_MAGIC
            || u16::from_le_bytes([bytes[8], bytes[9]]) != VERSION
            || bytes[11] != 0
        {
            return Err(AdaptorError::InvalidContext(
                "early terms binding header is not canonical",
            ));
        }
        let kind = EarlyTermsMessageKindV1::try_from(bytes[10])?;
        let context_commitment =
            exact_array::<32>("EarlyTermsBindingV1 context commitment", &bytes[12..44])?;
        if context_commitment == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "early terms context commitment must be nonzero",
            ));
        }
        Ok(Self {
            bytes,
            kind,
            context_commitment,
        })
    }

    /// Exact canonical bytes.
    pub const fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.bytes
    }

    /// Closed offer/accept kind.
    pub const fn kind(&self) -> EarlyTermsMessageKindV1 {
        self.kind
    }

    /// Store-authenticated context commitment.
    pub const fn context_commitment(&self) -> &[u8; 32] {
        &self.context_commitment
    }
}

/// Exact commitment to one participant's canonical share reveal.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EarlyShareCommitmentV1 {
    bytes: [u8; Self::ENCODED_LEN],
    participant_index: u16,
    context_commitment: [u8; 32],
    reveal_digest: [u8; 32],
}

impl EarlyShareCommitmentV1 {
    /// Exact canonical length.
    pub const ENCODED_LEN: usize = 76;

    /// Commit to the complete canonical reveal before either reveal is sent.
    ///
    /// The caller must durably retain those exact reveal bytes before
    /// transmitting the commitment: a freshly randomized proof cannot be
    /// regenerated later and still open this commitment.
    pub fn new(reveal: &EarlyShareRevealV1) -> Self {
        Self::from_parts(
            reveal.participant_index(),
            *reveal.context_commitment(),
            reveal.digest(),
        )
    }

    fn from_parts(
        participant_index: u16,
        context_commitment: [u8; 32],
        reveal_digest: [u8; 32],
    ) -> Self {
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[..8].copy_from_slice(SHARE_COMMIT_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&participant_index.to_le_bytes());
        bytes[12..44].copy_from_slice(&context_commitment);
        bytes[44..].copy_from_slice(&reveal_digest);
        Self {
            bytes,
            participant_index,
            context_commitment,
            reveal_digest,
        }
    }

    /// Parse the exact V1 encoding and reject an out-of-range participant.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("EarlyShareCommitmentV1", bytes)?;
        if &bytes[..8] != SHARE_COMMIT_MAGIC || u16::from_le_bytes([bytes[8], bytes[9]]) != VERSION
        {
            return Err(AdaptorError::InvalidContext(
                "early share commitment header is not canonical",
            ));
        }
        let participant_index = u16::from_le_bytes([bytes[10], bytes[11]]);
        let context_commitment =
            exact_array::<32>("EarlyShareCommitmentV1 context commitment", &bytes[12..44])?;
        let reveal_digest =
            exact_array::<32>("EarlyShareCommitmentV1 reveal digest", &bytes[44..76])?;
        if participant_index >= 16 || context_commitment == [0; 32] || reveal_digest == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "early share commitment fields are not canonical",
            ));
        }
        Ok(Self {
            bytes,
            participant_index,
            context_commitment,
            reveal_digest,
        })
    }

    /// Exact canonical bytes.
    pub const fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.bytes
    }

    /// Participant position in the canonical participant-ID roster.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Store-prepared session/roster/terms/recovery commitment.
    pub const fn context_commitment(&self) -> &[u8; 32] {
        &self.context_commitment
    }

    /// Digest of the exact reveal bytes.
    pub const fn reveal_digest(&self) -> &[u8; 32] {
        &self.reveal_digest
    }

    /// Whether this commitment opens to the supplied canonical reveal.
    pub fn opens(&self, reveal: &EarlyShareRevealV1) -> bool {
        self.participant_index == reveal.participant_index()
            && self.context_commitment == *reveal.context_commitment()
            && self.reveal_digest == reveal.digest()
    }
}

/// Exact wrapper around the real share statement and proof primitives.
#[derive(Clone, Eq, PartialEq)]
pub struct EarlyShareRevealV1 {
    bytes: [u8; Self::ENCODED_LEN],
    context_commitment: [u8; 32],
    statement: SharePoPStatementV1,
    proof: ShareProofV1,
    digest: [u8; 32],
}

impl EarlyShareRevealV1 {
    /// Exact canonical length.
    pub const ENCODED_LEN: usize =
        48 + SharePoPStatementV1::ENCODED_LEN + ShareProofV1::ENCODED_LEN;

    /// Wrap an already-bound statement and proof after verifying the relation.
    pub fn new(
        context_commitment: [u8; 32],
        statement: SharePoPStatementV1,
        proof: ShareProofV1,
    ) -> Result<Self> {
        if context_commitment == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "early share reveal context commitment must be nonzero",
            ));
        }
        if !verify_share_knowledge_v1(&statement, &proof)? {
            return Err(AdaptorError::VerificationFailed(
                "share reveal proof does not verify",
            ));
        }
        Self::from_verified_parts(context_commitment, statement, proof)
    }

    /// Parse and verify against a trusted chain and canonical participant roster.
    pub fn from_bytes(
        bytes: &[u8],
        trusted_chain_id: &TrustedChainIdV1,
        participant_roster: &[[u8; 32]],
        expected_context_commitment: &[u8; 32],
    ) -> Result<Self> {
        let (context_commitment, statement_bytes, proof_bytes) = split_reveal(bytes)?;
        if &context_commitment != expected_context_commitment {
            return Err(AdaptorError::InvalidContext(
                "share reveal differs from the prepared context",
            ));
        }
        let statement =
            SharePoPStatementV1::from_bytes(statement_bytes, trusted_chain_id, participant_roster)?;
        let proof = ShareProofV1::from_bytes(proof_bytes)?;
        Self::new(context_commitment, statement, proof)
    }

    /// Parse and verify against chain bytes already frozen by a retained
    /// authority.
    ///
    /// This verifier does not manufacture a [`TrustedChainIdV1`] and cannot be
    /// used to create signing context. It exists so a retained Store can
    /// reauthenticate an immutable journal after restart, when it has the
    /// original authenticated chain bytes but not the live chain-adapter token.
    pub fn from_bytes_against_frozen_context(
        bytes: &[u8],
        frozen_chain_id: &[u8; 32],
        participant_roster: &[[u8; 32]],
        expected_context_commitment: &[u8; 32],
    ) -> Result<Self> {
        let (context_commitment, statement_bytes, proof_bytes) = split_reveal(bytes)?;
        if &context_commitment != expected_context_commitment {
            return Err(AdaptorError::InvalidContext(
                "share reveal differs from the prepared context",
            ));
        }
        let statement = SharePoPStatementV1::from_bytes_against_frozen_chain(
            statement_bytes,
            frozen_chain_id,
            participant_roster,
        )?;
        let proof = ShareProofV1::from_bytes(proof_bytes)?;
        Self::new(context_commitment, statement, proof)
    }

    fn from_verified_parts(
        context_commitment: [u8; 32],
        statement: SharePoPStatementV1,
        proof: ShareProofV1,
    ) -> Result<Self> {
        let mut bytes = [0; Self::ENCODED_LEN];
        bytes[..8].copy_from_slice(SHARE_REVEAL_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(SharePoPStatementV1::ENCODED_LEN as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&(ShareProofV1::ENCODED_LEN as u16).to_le_bytes());
        bytes[16..48].copy_from_slice(&context_commitment);
        let statement_end = 48 + SharePoPStatementV1::ENCODED_LEN;
        bytes[48..statement_end].copy_from_slice(&statement.to_bytes());
        bytes[statement_end..].copy_from_slice(&proof.to_bytes());
        let digest = *blake2b_256(&bytes).as_bytes();
        if digest == [0; 32] {
            return Err(AdaptorError::InvalidContext(
                "early share reveal digest must be nonzero",
            ));
        }
        Ok(Self {
            bytes,
            context_commitment,
            statement,
            proof,
            digest,
        })
    }

    /// Exact canonical bytes.
    pub const fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        self.bytes
    }

    /// Digest committed by [`EarlyShareCommitmentV1`].
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Store-prepared session/roster/terms/recovery commitment.
    pub const fn context_commitment(&self) -> &[u8; 32] {
        &self.context_commitment
    }

    /// Participant position in the canonical participant-ID roster.
    pub fn participant_index(&self) -> u16 {
        self.statement.participant_index()
    }

    /// Verified real share-PoK statement.
    pub const fn statement(&self) -> &SharePoPStatementV1 {
        &self.statement
    }

    /// Verified real share-PoK proof.
    pub const fn proof(&self) -> &ShareProofV1 {
        &self.proof
    }
}

fn split_reveal(bytes: &[u8]) -> Result<([u8; 32], &[u8], &[u8])> {
    if bytes.len() != EarlyShareRevealV1::ENCODED_LEN {
        return Err(AdaptorError::InvalidLength {
            object: "EarlyShareRevealV1",
            expected: EarlyShareRevealV1::ENCODED_LEN,
            actual: bytes.len(),
        });
    }
    if &bytes[..8] != SHARE_REVEAL_MAGIC
        || u16::from_le_bytes([bytes[8], bytes[9]]) != VERSION
        || usize::from(u16::from_le_bytes([bytes[10], bytes[11]]))
            != SharePoPStatementV1::ENCODED_LEN
        || usize::from(u16::from_le_bytes([bytes[12], bytes[13]])) != ShareProofV1::ENCODED_LEN
        || bytes[14..16] != [0; 2]
    {
        return Err(AdaptorError::InvalidContext(
            "early share reveal header is not canonical",
        ));
    }
    let context_commitment =
        exact_array::<32>("EarlyShareRevealV1 context commitment", &bytes[16..48])?;
    if context_commitment == [0; 32] {
        return Err(AdaptorError::InvalidContext(
            "early share reveal context commitment must be nonzero",
        ));
    }
    let statement_end = 48 + SharePoPStatementV1::ENCODED_LEN;
    Ok((
        context_commitment,
        &bytes[48..statement_end],
        &bytes[statement_end..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prove_share_knowledge_v1, DirectionV1, SigningShareV1};
    use dom_core::Hash256;

    fn fixture() -> Result<(
        TrustedChainIdV1,
        Vec<[u8; 32]>,
        SharePoPStatementV1,
        ShareProofV1,
    )> {
        let chain = TrustedChainIdV1::from_authenticated_genesis(
            0x4455_6677,
            &Hash256::from_bytes([0x11; 32]),
        );
        let roster = vec![[0x21; 32], [0x42; 32]];
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let share = SigningShareV1::from_be_bytes(scalar)?;
        let statement = SharePoPStatementV1::new(
            &chain,
            [0x31; 32],
            &roster,
            DirectionV1::Initiator,
            0,
            share.public_key().clone(),
            [0x51; 32],
            [0x61; 32],
        )?;
        let proof = prove_share_knowledge_v1(&statement, &share)?;
        Ok((chain, roster, statement, proof))
    }

    #[test]
    fn terms_codec_is_exact_and_closed() -> Result<()> {
        for kind in [
            EarlyTermsMessageKindV1::Offer,
            EarlyTermsMessageKindV1::Accept,
        ] {
            let value = EarlyTermsBindingV1::new(kind, [0x41; 32])?;
            assert_eq!(EarlyTermsBindingV1::from_bytes(&value.to_bytes())?, value);
            let mut trailing = value.to_bytes().to_vec();
            trailing.push(0);
            assert!(EarlyTermsBindingV1::from_bytes(&trailing).is_err());
        }
        let mut unknown =
            EarlyTermsBindingV1::new(EarlyTermsMessageKindV1::Offer, [0x41; 32])?.to_bytes();
        unknown[10] = 3;
        assert!(EarlyTermsBindingV1::from_bytes(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn share_commit_opens_only_the_exact_verified_reveal() -> Result<()> {
        let (chain, roster, statement, proof) = fixture()?;
        let context = [0x71; 32];
        let reveal = EarlyShareRevealV1::new(context, statement, proof)?;
        let parsed = EarlyShareRevealV1::from_bytes(&reveal.to_bytes(), &chain, &roster, &context)?;
        let frozen = EarlyShareRevealV1::from_bytes_against_frozen_context(
            &reveal.to_bytes(),
            chain.as_bytes(),
            &roster,
            &context,
        )?;
        assert_eq!(parsed.to_bytes(), reveal.to_bytes());
        assert_eq!(frozen.to_bytes(), reveal.to_bytes());

        let commitment = EarlyShareCommitmentV1::new(&reveal);
        let reparsed = EarlyShareCommitmentV1::from_bytes(&commitment.to_bytes())?;
        assert!(reparsed.opens(&reveal));

        let mut tampered = reveal.to_bytes();
        tampered[EarlyShareRevealV1::ENCODED_LEN - 1] ^= 1;
        assert!(EarlyShareRevealV1::from_bytes(&tampered, &chain, &roster, &context).is_err());
        let mut trailing = reveal.to_bytes().to_vec();
        trailing.push(0);
        assert!(EarlyShareRevealV1::from_bytes(&trailing, &chain, &roster, &context).is_err());
        assert!(
            EarlyShareRevealV1::from_bytes(&reveal.to_bytes(), &chain, &roster, &[0x72; 32])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn share_reveal_refuses_wrong_chain_roster_and_context() -> Result<()> {
        let (chain, roster, statement, proof) = fixture()?;
        let context = [0x71; 32];
        let reveal = EarlyShareRevealV1::new(context, statement, proof)?;
        let other_chain = TrustedChainIdV1::from_authenticated_genesis(
            0x4455_6678,
            &Hash256::from_bytes([0x12; 32]),
        );
        assert!(EarlyShareRevealV1::from_bytes(
            &reveal.to_bytes(),
            &other_chain,
            &roster,
            &context
        )
        .is_err());
        assert!(EarlyShareRevealV1::from_bytes(
            &reveal.to_bytes(),
            &chain,
            &[[0x22; 32], [0x42; 32]],
            &context
        )
        .is_err());
        Ok(())
    }
}
