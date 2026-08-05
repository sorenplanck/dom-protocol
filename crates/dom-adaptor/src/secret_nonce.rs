//! Private one-shot secret two-nonce workflow.

use crate::{AdaptorError, Result, SigningShareV1};
use dom_crypto::{
    blake2b_256_tagged, scalar_bytes_are_canonical, scalar_from_wide_be,
    secret_scalar_mul_add_assign, secret_scalar_public_key, PartialSig, PublicKey,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SECRET_NONCE_AUX_TAG_V1: &str = "DOM:scriptless-secret-nonce-aux:v1";
const SECRET_NONCE_SEED_TAG_V1: &str = "DOM:scriptless-secret-nonce-seed:v1";
const SECRET_NONCE_WIDE_TAG_V1: &str = "DOM:scriptless-secret-nonce-wide:v1";
type SecretNonceScalarsV1 = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Operating-system-randomized derivation state retained only during the
/// pre-export retry loop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretNonceDerivationV1 {
    aux_rand_32: [u8; 32],
}

/// Private one-shot nonce pair owned exclusively by `dom-adaptor`.
///
/// The type deliberately implements no cloning, copying, debugging, display,
/// equality, ordering, or serialization. Partial signing consumes the pair.
pub(crate) struct SecretNoncePairV1 {
    first: Zeroizing<[u8; 32]>,
    second: Zeroizing<[u8; 32]>,
}

impl SecretNonceDerivationV1 {
    pub(crate) fn from_os_rng() -> Result<Self> {
        let mut aux_rand_32 = [0u8; 32];
        OsRng.try_fill_bytes(&mut aux_rand_32).map_err(|_| {
            aux_rand_32.zeroize();
            AdaptorError::RandomnessFailure
        })?;
        Ok(Self { aux_rand_32 })
    }

    pub(crate) fn derive_pair(
        &self,
        signing_share: &SigningShareV1,
        canonical_context_v1: &[u8],
    ) -> Option<SecretNoncePairV1> {
        derive_secret_nonce_pair_v1(signing_share, &self.aux_rand_32, canonical_context_v1)
            .map(|(first, second)| SecretNoncePairV1 { first, second })
    }

    #[cfg(test)]
    pub(crate) fn from_aux_for_test(aux_rand_32: [u8; 32]) -> Self {
        Self { aux_rand_32 }
    }
}

impl SecretNoncePairV1 {
    pub(crate) fn public_keys(&self) -> Result<(PublicKey, PublicKey)> {
        Ok((
            secret_scalar_public_key(&self.first)?,
            secret_scalar_public_key(&self.second)?,
        ))
    }

    pub(crate) fn sign_bound_partial(
        self,
        binding_factor: &PartialSig,
        challenge_be: &[u8; 32],
        signing_share: &SigningShareV1,
    ) -> Result<PartialSig> {
        if !scalar_bytes_are_canonical(challenge_be, false) {
            return Err(AdaptorError::InvalidTranscript(
                "partial signature challenge must be canonical and nonzero",
            ));
        }
        let mut partial = self.first;
        secret_scalar_mul_add_assign(&mut partial, &self.second, &binding_factor.to_bytes())?;
        secret_scalar_mul_add_assign(&mut partial, signing_share.as_be_bytes(), challenge_be)?;
        PartialSig::from_bytes(partial.as_ref()).map_err(Into::into)
    }

    pub(crate) fn from_be_bytes(first: [u8; 32], second: [u8; 32]) -> Result<Self> {
        let first = Zeroizing::new(first);
        let second = Zeroizing::new(second);
        if !scalar_bytes_are_canonical(&first, false) || !scalar_bytes_are_canonical(&second, false)
        {
            return Err(AdaptorError::InvalidContext(
                "nonce record contains a noncanonical scalar",
            ));
        }
        Ok(Self { first, second })
    }

    pub(crate) fn into_record_scalars(self) -> Zeroizing<[u8; 64]> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        bytes[..32].copy_from_slice(self.first.as_ref());
        bytes[32..].copy_from_slice(self.second.as_ref());
        bytes
    }
}

fn derive_secret_nonce_pair_v1(
    signing_share: &SigningShareV1,
    aux_rand_32: &[u8; 32],
    canonical_context_v1: &[u8],
) -> Option<SecretNonceScalarsV1> {
    let mut mask_hash = blake2b_256_tagged(SECRET_NONCE_AUX_TAG_V1, aux_rand_32);
    let mask = Zeroizing::new(*mask_hash.as_bytes());
    mask_hash.zeroize();

    32usize.checked_add(canonical_context_v1.len())?;
    let mut seed_input = Zeroizing::new(Vec::with_capacity(32 + canonical_context_v1.len()));
    seed_input.extend(
        signing_share
            .as_be_bytes()
            .iter()
            .zip(mask.iter())
            .map(|(secret, mask)| secret ^ mask),
    );
    seed_input.extend_from_slice(canonical_context_v1);
    let mut seed_hash = blake2b_256_tagged(SECRET_NONCE_SEED_TAG_V1, seed_input.as_ref());
    let seed = Zeroizing::new(*seed_hash.as_bytes());
    seed_hash.zeroize();

    fn expand(seed: &[u8; 32], index: u8) -> Zeroizing<[u8; 64]> {
        let mut input = Zeroizing::new([0u8; 34]);
        input[..32].copy_from_slice(seed);
        input[32] = index;

        input[33] = 0;
        let mut first = blake2b_256_tagged(SECRET_NONCE_WIDE_TAG_V1, input.as_ref());
        input[33] = 1;
        let mut second = blake2b_256_tagged(SECRET_NONCE_WIDE_TAG_V1, input.as_ref());

        let mut wide = Zeroizing::new([0u8; 64]);
        wide[..32].copy_from_slice(first.as_bytes());
        wide[32..].copy_from_slice(second.as_bytes());
        first.zeroize();
        second.zeroize();
        wide
    }

    let wide_first = expand(&seed, 0x01);
    let wide_second = expand(&seed, 0x02);
    match (
        scalar_from_wide_be(&wide_first),
        scalar_from_wide_be(&wide_second),
    ) {
        (Some(first), Some(second)) => Some((first, second)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_import_rejects_each_invalid_scalar_boundary() {
        const GROUP_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(SecretNoncePairV1::from_be_bytes([0u8; 32], one).is_err());
        assert!(SecretNoncePairV1::from_be_bytes(one, [0u8; 32]).is_err());
        assert!(SecretNoncePairV1::from_be_bytes(GROUP_ORDER, one).is_err());
        assert!(SecretNoncePairV1::from_be_bytes(one, [0xff; 32]).is_err());
    }
}
