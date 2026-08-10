//! Canonical adaptor pre-signature verification, adaptation, and extraction.

use crate::error::{exact_array, AdaptorError, Result};
use dom_crypto::{
    scriptless_adapt_signature, scriptless_extract_adaptor_secret,
    scriptless_extract_adaptor_secret_be_bytes, scriptless_verify_final_signature,
    scriptless_verify_pre_signature, PartialSig, PublicKey, SchnorrSignature, SecretScalar,
};
use zeroize::Zeroizing;

/// Canonical 65-byte cryptographic adaptor pre-signature core `R_hat || s_hat`.
///
/// This is distinct from the 162-byte session-bound transport object. The
/// type intentionally implements neither `Clone` nor `Debug`.
pub struct CoreAdaptorPreSignatureV1 {
    aggregate_nonce_hat: PublicKey,
    scalar_hat: PartialSig,
}

impl CoreAdaptorPreSignatureV1 {
    /// Exact canonical encoded length.
    pub const ENCODED_LEN: usize = 65;

    /// Parse exact core bytes with canonical point and scalar rejection.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("CoreAdaptorPreSignatureV1", bytes)?;
        Ok(Self {
            aggregate_nonce_hat: PublicKey::from_compressed_bytes(&bytes[..33])?,
            scalar_hat: PartialSig::from_bytes(&bytes[33..])?,
        })
    }

    /// Serialize exact `R_hat || s_hat` bytes.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..33].copy_from_slice(&self.aggregate_nonce_hat.to_compressed_bytes());
        bytes[33..].copy_from_slice(&self.scalar_hat.to_bytes());
        bytes
    }
}

/// Opaque adaptor secret with zeroization and no cloning, debug output, or
/// generic serialization.
pub struct AdaptorSecret(SecretScalar);

impl AdaptorSecret {
    /// Parse a canonical 32-byte big-endian adaptor scalar.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self> {
        SecretScalar::from_be_bytes(bytes)
            .map(Self)
            .map_err(Into::into)
    }

    /// Derive the adaptor point `T = t*G`.
    pub fn public_point(&self) -> Result<PublicKey> {
        self.0.public_key().map_err(Into::into)
    }
}

/// Canonical 162-byte Claim adaptor pre-signature payload.
///
/// This type intentionally implements neither `Clone` nor `Debug`; its scalar
/// is irreversible signing material and explicit serialization is the only
/// export path.
pub struct AdaptorPreSignatureV1 {
    claim_template_hash: [u8; 32],
    adaptor_point: PublicKey,
    aggregate_nonce_hat: PublicKey,
    scalar_hat: PartialSig,
    transcript_hash: [u8; 32],
}

impl AdaptorPreSignatureV1 {
    /// Canonical encoded length.
    pub const ENCODED_LEN: usize = 162;

    /// Construct a pre-signature from canonical fields.
    pub const fn new(
        claim_template_hash: [u8; 32],
        adaptor_point: PublicKey,
        aggregate_nonce_hat: PublicKey,
        scalar_hat: PartialSig,
        transcript_hash: [u8; 32],
    ) -> Self {
        Self {
            claim_template_hash,
            adaptor_point,
            aggregate_nonce_hat,
            scalar_hat,
            transcript_hash,
        }
    }

    /// Parse an exact canonical pre-signature payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("AdaptorPreSignatureV1", bytes)?;
        let mut claim_template_hash = [0u8; 32];
        claim_template_hash.copy_from_slice(&bytes[..32]);
        let adaptor_point = PublicKey::from_compressed_bytes(&bytes[32..65])?;
        let aggregate_nonce_hat = PublicKey::from_compressed_bytes(&bytes[65..98])?;
        let scalar_hat = PartialSig::from_bytes(&bytes[98..130])?;
        let mut transcript_hash = [0u8; 32];
        transcript_hash.copy_from_slice(&bytes[130..]);
        Ok(Self::new(
            claim_template_hash,
            adaptor_point,
            aggregate_nonce_hat,
            scalar_hat,
            transcript_hash,
        ))
    }

    /// Parse and validate the 162-byte object against an immutable Claim session.
    pub fn from_bytes_for_session(bytes: &[u8], context: &crate::SessionContextV1) -> Result<Self> {
        if context.purpose() != crate::PurposeV1::ClaimAdaptor {
            return Err(AdaptorError::InvalidTranscript(
                "session-bound adaptor pre-signature requires ClaimAdaptor",
            ));
        }
        let parsed = Self::from_bytes(bytes)?;
        if parsed.claim_template_hash() != context.template_hash()
            || parsed.transcript_hash() != context.transcript_hash()
            || context.adaptor_point() != Some(parsed.adaptor_point())
        {
            return Err(AdaptorError::InvalidTranscript(
                "adaptor pre-signature fields differ from the Claim session",
            ));
        }
        Ok(parsed)
    }

    /// Return the distinct 65-byte cryptographic core.
    pub fn core_bytes(&self) -> [u8; CoreAdaptorPreSignatureV1::ENCODED_LEN] {
        let mut bytes = [0u8; CoreAdaptorPreSignatureV1::ENCODED_LEN];
        bytes[..33].copy_from_slice(&self.aggregate_nonce_hat.to_compressed_bytes());
        bytes[33..].copy_from_slice(&self.scalar_hat.to_bytes());
        bytes
    }

    /// Serialize the exact canonical pre-signature payload.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[..32].copy_from_slice(&self.claim_template_hash);
        bytes[32..65].copy_from_slice(&self.adaptor_point.to_compressed_bytes());
        bytes[65..98].copy_from_slice(&self.aggregate_nonce_hat.to_compressed_bytes());
        bytes[98..130].copy_from_slice(&self.scalar_hat.to_bytes());
        bytes[130..].copy_from_slice(&self.transcript_hash);
        bytes
    }

    /// Verify the adaptor equation using the authoritative DOM challenge.
    pub fn verify(
        &self,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<bool> {
        if &self.claim_template_hash != expected_claim_template_hash {
            return Err(AdaptorError::InvalidTranscript(
                "adaptor pre-signature claim template does not match the session",
            ));
        }
        if &self.transcript_hash != expected_transcript_hash {
            return Err(AdaptorError::InvalidTranscript(
                "adaptor pre-signature transcript does not match the session",
            ));
        }
        scriptless_verify_pre_signature(
            &self.scalar_hat,
            &self.aggregate_nonce_hat,
            signing_key,
            &self.adaptor_point,
            chain_id,
            kernel_message,
        )
        .map_err(Into::into)
    }

    /// Verify, adapt, and verify the resulting standard DOM signature.
    pub fn adapt(
        &self,
        secret: &AdaptorSecret,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<SchnorrSignature> {
        if secret.public_point()? != self.adaptor_point {
            return Err(AdaptorError::VerificationFailed(
                "adaptor secret does not match the committed point",
            ));
        }
        if !self.verify(
            expected_claim_template_hash,
            expected_transcript_hash,
            signing_key,
            chain_id,
            kernel_message,
        )? {
            return Err(AdaptorError::VerificationFailed(
                "adaptor pre-signature equation",
            ));
        }
        let signature =
            scriptless_adapt_signature(&self.scalar_hat, &self.aggregate_nonce_hat, &secret.0)?;
        if !scriptless_verify_final_signature(&signature, signing_key, chain_id, kernel_message)? {
            return Err(AdaptorError::VerificationFailed(
                "adapted DOM Schnorr signature",
            ));
        }
        Ok(signature)
    }

    /// Verify both signatures, then extract and validate the adaptor secret.
    #[allow(clippy::too_many_arguments)]
    pub fn extract(
        &self,
        final_signature: &SchnorrSignature,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<AdaptorSecret> {
        self.verify_both_signatures(
            final_signature,
            expected_claim_template_hash,
            expected_transcript_hash,
            signing_key,
            chain_id,
            kernel_message,
        )?;
        scriptless_extract_adaptor_secret(
            final_signature,
            &self.scalar_hat,
            &self.aggregate_nonce_hat,
            &self.adaptor_point,
        )
        .map(AdaptorSecret)
        .map_err(Into::into)
    }

    /// Verify both signatures, extract the adaptor secret, and return its
    /// canonical big-endian bytes.
    ///
    /// Same verification as [`Self::extract`] — both go through the same
    /// private check and the same extraction in `dom-crypto`; the only
    /// difference is that this one hands back the 32 bytes instead of the
    /// opaque [`AdaptorSecret`].
    ///
    /// # Why this export exists, and why it is not a leak
    ///
    /// The extracted adaptor secret is the one secret scalar that is **public
    /// by construction**: it is `t = s - s_hat` over two signatures that are
    /// both already published, so any observer can compute it. Returning it
    /// discloses nothing the network does not already hold.
    ///
    /// It is also the value a cross-chain swap is built to deliver. The
    /// counterparty leg is claimed with exactly these bytes, so without an
    /// export path the DOM leg can prove it recovered the right `t` — by
    /// comparing the public point — but cannot hand it over, and the swap
    /// cannot complete. Recomputing `t` outside the authority would put the
    /// adaptor arithmetic in a second place; this keeps it in one.
    ///
    /// Nothing else becomes exportable: [`AdaptorSecret`] still has no byte
    /// accessor, `dom_crypto::SecretScalar` is unchanged, and these bytes are
    /// reachable only through a fully verified extraction. The value comes
    /// back in a [`Zeroizing`] buffer so it is wiped on drop.
    #[allow(clippy::too_many_arguments)]
    pub fn extract_revealed_secret_be_bytes(
        &self,
        final_signature: &SchnorrSignature,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>> {
        self.verify_both_signatures(
            final_signature,
            expected_claim_template_hash,
            expected_transcript_hash,
            signing_key,
            chain_id,
            kernel_message,
        )?;
        scriptless_extract_adaptor_secret_be_bytes(
            final_signature,
            &self.scalar_hat,
            &self.aggregate_nonce_hat,
            &self.adaptor_point,
        )
        .map_err(Into::into)
    }

    /// The pre-signature equation and the observed final signature, in that
    /// order. Shared by both extraction entry points so they can never drift
    /// apart: an export path that checked less than the opaque path would be
    /// exactly the wrong difference to have.
    #[allow(clippy::too_many_arguments)]
    fn verify_both_signatures(
        &self,
        final_signature: &SchnorrSignature,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<()> {
        if !self.verify(
            expected_claim_template_hash,
            expected_transcript_hash,
            signing_key,
            chain_id,
            kernel_message,
        )? {
            return Err(AdaptorError::VerificationFailed(
                "adaptor pre-signature equation",
            ));
        }
        if !scriptless_verify_final_signature(
            final_signature,
            signing_key,
            chain_id,
            kernel_message,
        )? {
            return Err(AdaptorError::VerificationFailed(
                "final DOM Schnorr signature",
            ));
        }
        Ok(())
    }

    /// Return the bound claim-template digest.
    pub const fn claim_template_hash(&self) -> &[u8; 32] {
        &self.claim_template_hash
    }

    /// Return the adaptor point.
    pub const fn adaptor_point(&self) -> &PublicKey {
        &self.adaptor_point
    }

    /// Return the tweaked aggregate nonce point.
    pub const fn aggregate_nonce_hat(&self) -> &PublicKey {
        &self.aggregate_nonce_hat
    }

    /// Return the bound transcript digest.
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }
}
