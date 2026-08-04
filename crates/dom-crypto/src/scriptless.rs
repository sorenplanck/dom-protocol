//! Narrow authoritative arithmetic boundary for Scriptless Contracts.
//!
//! This module deliberately exposes protocol operations instead of generic
//! curve arithmetic. It keeps `k256` private to `dom-crypto`, preserves DOM's
//! canonical SEC1 and big-endian scalar formats, and does not define nonce
//! derivation or persistence policy.

#[cfg(feature = "test-helpers")]
use crate::hash::blake2b_256_tagged;
use crate::keys::PublicKey;
use crate::schnorr::{
    compressed_to_projective, is_scalar_valid, projective_to_compressed, scalar_from_bytes,
};
use crate::{schnorr_challenge, schnorr_verify, PartialSig, SchnorrSignature};
use dom_core::DomError;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::PrimeField;
use k256::ProjectivePoint;
#[cfg(feature = "test-helpers")]
use rand::{rngs::OsRng, RngCore};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "test-helpers")]
const SECRET_NONCE_AUX_TAG_V1: &str = "DOM:scriptless-secret-nonce-aux:v1";
#[cfg(feature = "test-helpers")]
const SECRET_NONCE_SEED_TAG_V1: &str = "DOM:scriptless-secret-nonce-seed:v1";
#[cfg(feature = "test-helpers")]
const SECRET_NONCE_WIDE_TAG_V1: &str = "DOM:scriptless-secret-nonce-wide:v1";

/// A canonical, nonzero secp256k1 scalar held as secret material.
///
/// The value is encoded as 32-byte big-endian data. This type intentionally
/// implements neither `Clone`, `Debug`, nor generic serialization. It is
/// zeroized on drop. Construction validates the canonical interval `[1,n-1]`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ScriptlessSecretScalar([u8; 32]);

impl ScriptlessSecretScalar {
    /// Parse canonical big-endian secret scalar bytes.
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Result<Self, DomError> {
        if !is_scalar_valid(&bytes) {
            bytes.zeroize();
            return Err(DomError::Invalid(
                "scriptless secret scalar is zero or >= n".into(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Derive the canonical compressed public point `secret * G`.
    pub fn public_key(&self) -> PublicKey {
        let scalar =
            Zeroizing::new(scalar_from_bytes(&self.0).expect("secret scalar is already validated"));
        let compressed = projective_to_compressed(&(ProjectivePoint::GENERATOR * *scalar));
        PublicKey::from_compressed_bytes(&compressed)
            .expect("a nonzero generator multiple is a canonical public key")
    }

    pub(crate) fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Reduce an exact 512-bit big-endian integer modulo the secp256k1 group order.
///
/// This is the only generic arithmetic extension authorized for the secret
/// two-nonce KDF. It delegates to `k256`'s constant-time `Reduce<U512>` inside
/// `dom-crypto`; callers never receive generic scalar arithmetic. A zero result
/// is rejected. The input is borrowed and remains the caller's responsibility
/// to zeroize after this function returns.
pub fn scalar_from_wide_be(input: &[u8; 64]) -> Option<ScriptlessSecretScalar> {
    let mut wide = k256::WideBytes::default();
    wide.copy_from_slice(input);
    let mut reduced = <k256::Scalar as Reduce<U512>>::reduce_bytes(&wide);
    wide.zeroize();

    if bool::from(reduced.is_zero()) {
        reduced.zeroize();
        return None;
    }

    let bytes: [u8; 32] = reduced.to_repr().into();
    reduced.zeroize();
    ScriptlessSecretScalar::from_be_bytes(bytes).ok()
}

/// Derive the ratified V1 secret two-nonce pair through DOM's tagged-hash and
/// constant-time scalar-reduction boundaries.
///
/// `canonical_context_v1` must already have passed the validation and exact
/// encoding rules defined by NAR-001. The caller owns and must zeroize the
/// borrowed auxiliary randomness after the complete derivation or retry loop.
/// A `None` result means at least one wide reduction produced zero; the caller
/// may retry only by incrementing the context retry counter before public
/// material exists.
#[cfg(feature = "test-helpers")]
fn derive_secret_nonce_pair_v1(
    signing_share: &ScriptlessSecretScalar,
    aux_rand_32: &[u8; 32],
    canonical_context_v1: &[u8],
) -> Option<(ScriptlessSecretScalar, ScriptlessSecretScalar)> {
    let mut mask_hash = blake2b_256_tagged(SECRET_NONCE_AUX_TAG_V1, aux_rand_32);
    let mask = Zeroizing::new(*mask_hash.as_bytes());
    mask_hash.zeroize();

    let mut masked_signing_share = Zeroizing::new([0u8; 32]);
    for ((output, secret), mask_byte) in masked_signing_share
        .iter_mut()
        .zip(signing_share.as_be_bytes())
        .zip(mask.iter())
    {
        *output = *secret ^ *mask_byte;
    }

    let mut seed_input = Zeroizing::new(Vec::with_capacity(
        32usize.checked_add(canonical_context_v1.len())?,
    ));
    seed_input.extend_from_slice(masked_signing_share.as_ref());
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
    let first = scalar_from_wide_be(&wide_first);
    let second = scalar_from_wide_be(&wide_second);
    match (first, second) {
        (Some(first), Some(second)) => Some((first, second)),
        _ => None,
    }
}

/// Opaque operating-system-randomized nonce derivation state for test evidence.
///
/// This type is excluded from default production builds because G1b durable
/// authorization must own the production nonce lifecycle. The same private
/// auxiliary value is retained only across the pre-export retry loop and is
/// zeroized when this value is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg(feature = "test-helpers")]
pub struct ScriptlessNonceDerivationV1 {
    aux_rand_32: [u8; 32],
}

/// Opaque one-shot secret nonce pair for test evidence.
///
/// The type intentionally implements no cloning, copying, debugging, display,
/// equality, ordering, or serialization. Signing consumes the complete pair.
/// This type is absent from default production builds until G1b integration.
#[cfg(feature = "test-helpers")]
pub struct ScriptlessSecretNoncePairV1 {
    first: ScriptlessSecretScalar,
    second: ScriptlessSecretScalar,
}

#[cfg(feature = "test-helpers")]
impl ScriptlessSecretNoncePairV1 {
    /// Derive both canonical public nonce points.
    pub fn public_keys(&self) -> (PublicKey, PublicKey) {
        (self.first.public_key(), self.second.public_key())
    }

    /// Consume the pair and produce exactly one bound partial signature.
    pub fn sign_bound_partial(
        self,
        binding_factor: &PartialSig,
        challenge_be: &[u8; 32],
        signing_share: &ScriptlessSecretScalar,
    ) -> Result<PartialSig, DomError> {
        sign_bound_partial_once(
            &self.first,
            &self.second,
            binding_factor,
            challenge_be,
            signing_share,
        )
    }
}

#[cfg(feature = "test-helpers")]
impl ScriptlessNonceDerivationV1 {
    /// Acquire fresh auxiliary randomness from the operating-system CSPRNG.
    pub fn from_os_rng() -> Result<Self, DomError> {
        let mut aux_rand_32 = [0u8; 32];
        OsRng.try_fill_bytes(&mut aux_rand_32).map_err(|_| {
            aux_rand_32.zeroize();
            DomError::Internal("operating-system CSPRNG failed".into())
        })?;
        Ok(Self { aux_rand_32 })
    }

    /// Derive one pair for an already validated canonical context encoding.
    /// A zero reduction returns `None` so the owning pre-export retry loop can
    /// increment its checked counter and call this method again.
    pub fn derive_pair(
        &self,
        signing_share: &ScriptlessSecretScalar,
        canonical_context_v1: &[u8],
    ) -> Option<ScriptlessSecretNoncePairV1> {
        derive_secret_nonce_pair_v1(signing_share, &self.aux_rand_32, canonical_context_v1)
            .map(|(first, second)| ScriptlessSecretNoncePairV1 { first, second })
    }

    /// Build deterministic derivation state for authenticated tests only.
    #[cfg(feature = "test-helpers")]
    #[doc(hidden)]
    pub fn from_aux_for_test(aux_rand_32: [u8; 32]) -> Self {
        Self { aux_rand_32 }
    }
}

impl ConstantTimeEq for ScriptlessSecretScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Verify the DOM adaptor pre-signature equation.
///
/// This checks `s_hat*G == R_hat + e*X - T`, where `e` is produced by the
/// authoritative DOM kernel challenge.
pub fn scriptless_verify_pre_signature(
    scalar_hat: &PartialSig,
    aggregate_nonce_hat: &PublicKey,
    signing_key: &PublicKey,
    adaptor_point: &PublicKey,
    chain_id: &[u8; 32],
    message: &[u8],
) -> Result<bool, DomError> {
    let challenge = schnorr_challenge(
        &aggregate_nonce_hat.to_compressed_bytes(),
        signing_key,
        chain_id,
        message,
    );
    let challenge_bytes = *challenge.as_bytes();
    if !is_scalar_valid(&challenge_bytes) {
        return Err(DomError::Invalid(
            "DOM challenge is not a canonical nonzero scalar".into(),
        ));
    }

    let s_hat = scalar_from_bytes(&scalar_hat.to_bytes())
        .ok_or_else(|| DomError::Invalid("pre-signature scalar is invalid".into()))?;
    let e = scalar_from_bytes(&challenge_bytes)
        .ok_or_else(|| DomError::Invalid("DOM challenge scalar is invalid".into()))?;
    let r_hat = compressed_to_projective(&aggregate_nonce_hat.to_compressed_bytes())?;
    let x = compressed_to_projective(&signing_key.to_compressed_bytes())?;
    let adaptor = compressed_to_projective(&adaptor_point.to_compressed_bytes())?;

    Ok(ProjectivePoint::GENERATOR * s_hat == r_hat + x * e - adaptor)
}

/// Adapt a scalar pre-signature with `t` to a standard DOM signature.
///
/// The returned value uses the unchanged DOM `R33 || s32_be` format. The
/// caller remains responsible for verifying the pre-signature first.
pub fn scriptless_adapt_signature(
    scalar_hat: &PartialSig,
    aggregate_nonce_hat: &PublicKey,
    adaptor_secret: &ScriptlessSecretScalar,
) -> Result<SchnorrSignature, DomError> {
    let s_hat = Zeroizing::new(
        scalar_from_bytes(&scalar_hat.to_bytes())
            .ok_or_else(|| DomError::Invalid("pre-signature scalar is invalid".into()))?,
    );
    let t = Zeroizing::new(
        scalar_from_bytes(adaptor_secret.as_be_bytes())
            .ok_or_else(|| DomError::Invalid("adaptor secret is invalid".into()))?,
    );
    let adapted = Zeroizing::new(*s_hat + *t);
    if bool::from(adapted.is_zero()) {
        return Err(DomError::Invalid("adapted signature scalar is zero".into()));
    }

    let mut bytes = [0u8; 65];
    bytes[..33].copy_from_slice(&aggregate_nonce_hat.to_compressed_bytes());
    bytes[33..].copy_from_slice(&<[u8; 32]>::from(adapted.to_repr()));
    SchnorrSignature::from_bytes(&bytes)
}

/// Extract and validate the adaptor secret from a final DOM signature.
pub fn scriptless_extract_adaptor_secret(
    final_signature: &SchnorrSignature,
    scalar_hat: &PartialSig,
    aggregate_nonce_hat: &PublicKey,
    adaptor_point: &PublicKey,
) -> Result<ScriptlessSecretScalar, DomError> {
    if final_signature.r_compressed() != &aggregate_nonce_hat.to_compressed_bytes() {
        return Err(DomError::Invalid(
            "final signature nonce differs from the pre-signature nonce".into(),
        ));
    }

    let signature_bytes = final_signature.to_bytes();
    let mut final_scalar_bytes = [0u8; 32];
    final_scalar_bytes.copy_from_slice(&signature_bytes[33..]);
    let final_scalar = Zeroizing::new(
        scalar_from_bytes(&final_scalar_bytes)
            .ok_or_else(|| DomError::Invalid("final signature scalar is invalid".into()))?,
    );
    let pre_scalar = Zeroizing::new(
        scalar_from_bytes(&scalar_hat.to_bytes())
            .ok_or_else(|| DomError::Invalid("pre-signature scalar is invalid".into()))?,
    );
    let extracted = Zeroizing::new(*final_scalar - *pre_scalar);
    if bool::from(extracted.is_zero()) {
        return Err(DomError::Invalid("extracted adaptor secret is zero".into()));
    }

    let bytes: [u8; 32] = extracted.to_repr().into();
    let secret = ScriptlessSecretScalar::from_be_bytes(bytes)?;
    if secret.public_key() != *adaptor_point {
        return Err(DomError::Invalid(
            "extracted scalar does not match the adaptor point".into(),
        ));
    }
    Ok(secret)
}

/// Compute the bound public nonce `R1 + b*R2` using DOM point arithmetic.
pub fn scriptless_bind_public_nonces(
    first: &PublicKey,
    second: &PublicKey,
    binding_factor: &PartialSig,
) -> Result<PublicKey, DomError> {
    let r1 = compressed_to_projective(&first.to_compressed_bytes())?;
    let r2 = compressed_to_projective(&second.to_compressed_bytes())?;
    let binding = scalar_from_bytes(&binding_factor.to_bytes())
        .ok_or_else(|| DomError::Invalid("binding factor is invalid".into()))?;
    let bound = r1 + r2 * binding;
    if bool::from(bound.is_identity()) {
        return Err(DomError::Invalid(
            "bound public nonce is the point at infinity".into(),
        ));
    }
    PublicKey::from_compressed_bytes(&projective_to_compressed(&bound))
}

/// Add canonical public points and reject an empty set or identity result.
pub fn scriptless_add_public_points(points: &[PublicKey]) -> Result<PublicKey, DomError> {
    if points.is_empty() {
        return Err(DomError::Malformed(
            "cannot aggregate an empty Scriptless point set".into(),
        ));
    }
    let mut sum = ProjectivePoint::IDENTITY;
    for point in points {
        sum += compressed_to_projective(&point.to_compressed_bytes())?;
    }
    if bool::from(sum.is_identity()) {
        return Err(DomError::Invalid(
            "aggregated Scriptless point is the point at infinity".into(),
        ));
    }
    PublicKey::from_compressed_bytes(&projective_to_compressed(&sum))
}

/// Produce `k1 + b*k2 + e*x` for a participant through the authoritative DOM
/// scalar boundary.
///
/// One-shot ownership is enforced by the `dom-adaptor` wrapper that consumes
/// its opaque nonce pair before calling this operation.
#[cfg(feature = "test-helpers")]
fn sign_bound_partial_once(
    first_nonce: &ScriptlessSecretScalar,
    second_nonce: &ScriptlessSecretScalar,
    binding_factor: &PartialSig,
    challenge_be: &[u8; 32],
    signing_share: &ScriptlessSecretScalar,
) -> Result<PartialSig, DomError> {
    if !is_scalar_valid(challenge_be) {
        return Err(DomError::Invalid(
            "partial signature challenge is zero or >= n".into(),
        ));
    }
    let first = Zeroizing::new(
        scalar_from_bytes(first_nonce.as_be_bytes())
            .ok_or_else(|| DomError::Invalid("first secret nonce is invalid".into()))?,
    );
    let second = Zeroizing::new(
        scalar_from_bytes(second_nonce.as_be_bytes())
            .ok_or_else(|| DomError::Invalid("second secret nonce is invalid".into()))?,
    );
    let binding = scalar_from_bytes(&binding_factor.to_bytes())
        .ok_or_else(|| DomError::Invalid("binding factor is invalid".into()))?;
    let challenge = scalar_from_bytes(challenge_be)
        .ok_or_else(|| DomError::Invalid("partial signature challenge is invalid".into()))?;
    let share = Zeroizing::new(
        scalar_from_bytes(signing_share.as_be_bytes())
            .ok_or_else(|| DomError::Invalid("signing share is invalid".into()))?,
    );
    let partial = Zeroizing::new(*first + binding * *second + challenge * *share);
    if bool::from(partial.is_zero()) {
        return Err(DomError::Invalid(
            "participant partial signature is zero".into(),
        ));
    }
    PartialSig::from_bytes(&<[u8; 32]>::from(partial.to_repr()))
}

/// Aggregate participant partial scalars without constructing a final
/// signature or changing the aggregate nonce.
pub fn scriptless_aggregate_partial_scalars(
    partials: &[PartialSig],
) -> Result<PartialSig, DomError> {
    if partials.is_empty() {
        return Err(DomError::Malformed(
            "cannot aggregate an empty partial signature set".into(),
        ));
    }
    let mut sum = Zeroizing::new(k256::Scalar::ZERO);
    for partial in partials {
        *sum += scalar_from_bytes(&partial.to_bytes())
            .ok_or_else(|| DomError::Invalid("partial signature scalar is invalid".into()))?;
    }
    if bool::from(sum.is_zero()) {
        return Err(DomError::Invalid(
            "aggregated pre-signature scalar is zero".into(),
        ));
    }
    PartialSig::from_bytes(&<[u8; 32]>::from(sum.to_repr()))
}

/// Verify `s_i*G == R_i + e*X_i` for a bound partial signature.
///
/// `challenge_be` must be the exact output of the authoritative aggregate DOM
/// challenge. No reduction or retry is performed.
pub fn scriptless_verify_bound_partial(
    partial: &PartialSig,
    bound_public_nonce: &PublicKey,
    participant_key: &PublicKey,
    challenge_be: &[u8; 32],
) -> Result<bool, DomError> {
    if !is_scalar_valid(challenge_be) {
        return Err(DomError::Invalid(
            "partial signature challenge is zero or >= n".into(),
        ));
    }
    let s = scalar_from_bytes(&partial.to_bytes())
        .ok_or_else(|| DomError::Invalid("partial signature scalar is invalid".into()))?;
    let challenge = scalar_from_bytes(challenge_be)
        .ok_or_else(|| DomError::Invalid("partial signature challenge is invalid".into()))?;
    let nonce = compressed_to_projective(&bound_public_nonce.to_compressed_bytes())?;
    let public_key = compressed_to_projective(&participant_key.to_compressed_bytes())?;
    Ok(ProjectivePoint::GENERATOR * s == nonce + public_key * challenge)
}

/// Verify a final signature with the authoritative DOM Schnorr verifier.
pub fn scriptless_verify_final_signature(
    signature: &SchnorrSignature,
    signing_key: &PublicKey,
    chain_id: &[u8; 32],
    message: &[u8],
) -> Result<bool, DomError> {
    schnorr_verify(signature, signing_key, chain_id, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretKey;

    fn scalar_bytes(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    fn point_from_scalar(value: u8) -> PublicKey {
        SecretKey::from_bytes(&scalar_bytes(value))
            .expect("small test scalar is canonical")
            .public_key()
    }

    #[test]
    fn scriptless_adaptor_equation_adapts_and_extracts() {
        let signing_secret = scalar_from_bytes(&scalar_bytes(7)).expect("x");
        let signing_key = point_from_scalar(7);
        let nonce = scalar_from_bytes(&scalar_bytes(11)).expect("k");
        let adaptor_secret = ScriptlessSecretScalar::from_be_bytes(scalar_bytes(13)).expect("t");
        let adaptor_point = adaptor_secret.public_key();
        let aggregate_nonce_hat_point = ProjectivePoint::GENERATOR * nonce
            + compressed_to_projective(&adaptor_point.to_compressed_bytes()).expect("T");
        let aggregate_nonce_hat =
            PublicKey::from_compressed_bytes(&projective_to_compressed(&aggregate_nonce_hat_point))
                .expect("R_hat");
        let chain_id = [0xA5; 32];
        let message = [0x5A; 32];
        let challenge_bytes = *schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            &signing_key,
            &chain_id,
            &message,
        )
        .as_bytes();
        let challenge = scalar_from_bytes(&challenge_bytes).expect("canonical challenge");
        let scalar_hat_bytes: [u8; 32] = (nonce + challenge * signing_secret).to_repr().into();
        let scalar_hat = PartialSig::from_bytes(&scalar_hat_bytes).expect("s_hat");

        assert!(scriptless_verify_pre_signature(
            &scalar_hat,
            &aggregate_nonce_hat,
            &signing_key,
            &adaptor_point,
            &chain_id,
            &message,
        )
        .expect("pre-signature verification"));
        let signature =
            scriptless_adapt_signature(&scalar_hat, &aggregate_nonce_hat, &adaptor_secret)
                .expect("adaptation");
        assert!(
            scriptless_verify_final_signature(&signature, &signing_key, &chain_id, &message,)
                .expect("final verification")
        );
        let extracted = scriptless_extract_adaptor_secret(
            &signature,
            &scalar_hat,
            &aggregate_nonce_hat,
            &adaptor_point,
        )
        .expect("extraction");
        assert!(bool::from(extracted.ct_eq(&adaptor_secret)));
    }

    #[test]
    fn scriptless_bound_nonce_and_partial_equation_are_consistent() {
        let first = point_from_scalar(3);
        let second = point_from_scalar(5);
        let binding = PartialSig::from_bytes(&scalar_bytes(7)).expect("b");
        let bound = scriptless_bind_public_nonces(&first, &second, &binding).expect("R_i");
        assert_eq!(bound, point_from_scalar(38));

        let participant_key = point_from_scalar(11);
        let challenge = scalar_bytes(13);
        let partial = PartialSig::from_bytes(&scalar_bytes(181)).expect("s_i");
        assert!(
            scriptless_verify_bound_partial(&partial, &bound, &participant_key, &challenge,)
                .expect("partial verification")
        );

        let wrong = PartialSig::from_bytes(&scalar_bytes(180)).expect("wrong s_i");
        assert!(
            !scriptless_verify_bound_partial(&wrong, &bound, &participant_key, &challenge,)
                .expect("negative partial verification")
        );
    }

    #[test]
    fn scriptless_secret_scalar_rejects_boundaries() {
        assert!(ScriptlessSecretScalar::from_be_bytes([0u8; 32]).is_err());
        assert!(ScriptlessSecretScalar::from_be_bytes([0xFF; 32]).is_err());
    }

    #[test]
    fn wide_scalar_reduction_is_big_endian_and_rejects_zero() {
        assert!(scalar_from_wide_be(&[0u8; 64]).is_none());

        let mut one = [0u8; 64];
        one[63] = 1;
        let reduced_one = scalar_from_wide_be(&one).expect("one remains one");
        assert_eq!(reduced_one.as_be_bytes(), &scalar_bytes(1));

        let order = secp256k1::constants::CURVE_ORDER;
        let mut exact_order = [0u8; 64];
        exact_order[32..].copy_from_slice(&order);
        assert!(scalar_from_wide_be(&exact_order).is_none());

        let mut order_plus_one = exact_order;
        order_plus_one[63] = order_plus_one[63].checked_add(1).expect("order low byte");
        let reduced = scalar_from_wide_be(&order_plus_one).expect("n + 1 reduces to one");
        assert_eq!(reduced.as_be_bytes(), &scalar_bytes(1));

        let mut high_bit = [0u8; 64];
        high_bit[0] = 0x80;
        let high = scalar_from_wide_be(&high_bit).expect("2^511 has a nonzero residue");
        assert_ne!(high.as_be_bytes(), &[0u8; 32]);
    }

    #[test]
    fn all_sixteen_sec1_parity_combinations_preserve_exact_dom_encoding() {
        use std::collections::BTreeSet;

        let chain_id = [0xA5; 32];
        let message = [0x5A; 32];
        let mut covered = BTreeSet::new();

        'outer: for signing_value in 1u8..=24 {
            for nonce_value in 1u8..=24 {
                for adaptor_value in 1u8..=24 {
                    let signing_secret =
                        scalar_from_bytes(&scalar_bytes(signing_value)).expect("x");
                    let signing_key = point_from_scalar(signing_value);
                    let nonce = scalar_from_bytes(&scalar_bytes(nonce_value)).expect("k");
                    let nonce_point = point_from_scalar(nonce_value);
                    let adaptor_secret =
                        ScriptlessSecretScalar::from_be_bytes(scalar_bytes(adaptor_value))
                            .expect("t");
                    let adaptor_point = adaptor_secret.public_key();
                    let aggregate_nonce_hat_point = ProjectivePoint::GENERATOR * nonce
                        + compressed_to_projective(&adaptor_point.to_compressed_bytes())
                            .expect("T");
                    if bool::from(aggregate_nonce_hat_point.is_identity()) {
                        continue;
                    }
                    let aggregate_nonce_hat = PublicKey::from_compressed_bytes(
                        &projective_to_compressed(&aggregate_nonce_hat_point),
                    )
                    .expect("R_hat");
                    let parity = (
                        signing_key.to_compressed_bytes()[0],
                        nonce_point.to_compressed_bytes()[0],
                        adaptor_point.to_compressed_bytes()[0],
                        aggregate_nonce_hat.to_compressed_bytes()[0],
                    );
                    if !covered.insert(parity) {
                        continue;
                    }

                    let challenge_bytes = *schnorr_challenge(
                        &aggregate_nonce_hat.to_compressed_bytes(),
                        &signing_key,
                        &chain_id,
                        &message,
                    )
                    .as_bytes();
                    let challenge = scalar_from_bytes(&challenge_bytes).expect("challenge");
                    let scalar_hat_value = nonce + challenge * signing_secret;
                    if bool::from(scalar_hat_value.is_zero()) {
                        covered.remove(&parity);
                        continue;
                    }
                    let scalar_hat =
                        PartialSig::from_bytes(&<[u8; 32]>::from(scalar_hat_value.to_repr()))
                            .expect("s_hat");
                    assert!(scriptless_verify_pre_signature(
                        &scalar_hat,
                        &aggregate_nonce_hat,
                        &signing_key,
                        &adaptor_point,
                        &chain_id,
                        &message,
                    )
                    .expect("pre-signature"));
                    let signature = scriptless_adapt_signature(
                        &scalar_hat,
                        &aggregate_nonce_hat,
                        &adaptor_secret,
                    )
                    .expect("adaptation");
                    assert_eq!(
                        signature.r_compressed(),
                        &aggregate_nonce_hat.to_compressed_bytes(),
                        "R_hat SEC1 bytes must be preserved without normalization"
                    );
                    assert!(scriptless_verify_final_signature(
                        &signature,
                        &signing_key,
                        &chain_id,
                        &message,
                    )
                    .expect("real DOM verifier"));
                    if covered.len() == 16 {
                        break 'outer;
                    }
                }
            }
        }
        assert_eq!(covered.len(), 16, "all four-bit SEC1 parity cases");
    }

    #[test]
    fn ten_thousand_deterministic_adapt_extract_cycles_pass_real_verifier() {
        let chain_id = [0xA5; 32];

        for case in 0u32..10_000 {
            let signing_value = ((case % 251) + 1) as u8;
            let nonce_value = (((case * 7) % 251) + 1) as u8;
            let adaptor_value = (((case * 13) % 251) + 1) as u8;
            let signing_secret =
                scalar_from_bytes(&scalar_bytes(signing_value)).expect("canonical signing scalar");
            let signing_key = point_from_scalar(signing_value);
            let nonce =
                scalar_from_bytes(&scalar_bytes(nonce_value)).expect("canonical nonce scalar");
            let adaptor_secret = ScriptlessSecretScalar::from_be_bytes(scalar_bytes(adaptor_value))
                .expect("canonical adaptor scalar");
            let adaptor_point = adaptor_secret.public_key();
            let aggregate_nonce_hat_point = ProjectivePoint::GENERATOR * nonce
                + compressed_to_projective(&adaptor_point.to_compressed_bytes())
                    .expect("canonical adaptor point");
            assert!(
                !bool::from(aggregate_nonce_hat_point.is_identity()),
                "case {case} must not produce the identity aggregate nonce"
            );
            let aggregate_nonce_hat = PublicKey::from_compressed_bytes(&projective_to_compressed(
                &aggregate_nonce_hat_point,
            ))
            .expect("canonical aggregate nonce");
            let message = case.to_le_bytes();
            let challenge_bytes = *schnorr_challenge(
                &aggregate_nonce_hat.to_compressed_bytes(),
                &signing_key,
                &chain_id,
                &message,
            )
            .as_bytes();
            let challenge = scalar_from_bytes(&challenge_bytes)
                .unwrap_or_else(|| panic!("case {case} challenge must be canonical"));
            let scalar_hat_value = nonce + challenge * signing_secret;
            assert!(
                !bool::from(scalar_hat_value.is_zero()),
                "case {case} pre-signature scalar must not be zero"
            );
            let scalar_hat_bytes: [u8; 32] = scalar_hat_value.to_repr().into();
            let scalar_hat = PartialSig::from_bytes(&scalar_hat_bytes)
                .unwrap_or_else(|error| panic!("case {case} pre-signature: {error}"));

            assert!(
                scriptless_verify_pre_signature(
                    &scalar_hat,
                    &aggregate_nonce_hat,
                    &signing_key,
                    &adaptor_point,
                    &chain_id,
                    &message,
                )
                .unwrap_or_else(|error| panic!("case {case} pre-signature verify: {error}")),
                "case {case} pre-signature equation"
            );
            let final_signature =
                scriptless_adapt_signature(&scalar_hat, &aggregate_nonce_hat, &adaptor_secret)
                    .unwrap_or_else(|error| panic!("case {case} adaptation: {error}"));
            assert!(
                scriptless_verify_final_signature(
                    &final_signature,
                    &signing_key,
                    &chain_id,
                    &message,
                )
                .unwrap_or_else(|error| panic!("case {case} final verification: {error}")),
                "case {case} final signature"
            );
            let extracted = scriptless_extract_adaptor_secret(
                &final_signature,
                &scalar_hat,
                &aggregate_nonce_hat,
                &adaptor_point,
            )
            .unwrap_or_else(|error| panic!("case {case} extraction: {error}"));
            assert_eq!(
                extracted.public_key(),
                adaptor_point,
                "case {case} extract(adapt(presign)) must recover t"
            );
        }
    }
}
