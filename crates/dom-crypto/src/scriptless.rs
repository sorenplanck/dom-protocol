//! Narrow authoritative arithmetic boundary for Scriptless Contracts.
//!
//! This module deliberately exposes protocol operations instead of generic
//! curve arithmetic. It keeps `k256` private to `dom-crypto`, preserves DOM's
//! canonical SEC1 and big-endian scalar formats, and does not define nonce
//! derivation or persistence policy.

use crate::keys::PublicKey;
use crate::schnorr::{
    compressed_to_projective, is_scalar_canonical_allow_zero, is_scalar_valid,
    projective_to_compressed, scalar_from_bytes,
};
use crate::{schnorr_challenge, schnorr_verify, PartialSig, SchnorrSignature};
use dom_core::DomError;
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::PrimeField;
use k256::ProjectivePoint;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A canonical, nonzero secp256k1 scalar held as secret material.
///
/// The value is encoded as 32-byte big-endian data. This type intentionally
/// implements neither `Clone`, `Debug`, nor generic serialization. It is
/// zeroized on drop. Construction validates the canonical interval `[1,n-1]`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar([u8; 32]);

impl SecretScalar {
    /// Parse canonical big-endian secret scalar bytes.
    pub fn from_be_bytes(mut bytes: [u8; 32]) -> Result<Self, DomError> {
        if !is_scalar_valid(&bytes) {
            bytes.zeroize();
            return Err(DomError::Invalid("secret scalar is zero or >= n".into()));
        }
        Ok(Self(bytes))
    }

    /// Derive the canonical compressed public point `secret * G`.
    pub fn public_key(&self) -> Result<PublicKey, DomError> {
        let scalar = Zeroizing::new(
            scalar_from_bytes(&self.0)
                .ok_or_else(|| DomError::Invalid("secret scalar is noncanonical".into()))?,
        );
        let compressed = projective_to_compressed(&(ProjectivePoint::GENERATOR * *scalar));
        PublicKey::from_compressed_bytes(&compressed)
    }

    fn as_be_bytes(&self) -> &[u8; 32] {
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
pub fn scalar_from_wide_be(input: &[u8; 64]) -> Option<Zeroizing<[u8; 32]>> {
    let mut wide = k256::WideBytes::default();
    wide.copy_from_slice(input);
    let mut reduced = <k256::Scalar as Reduce<U512>>::reduce_bytes(&wide);
    wide.zeroize();

    if bool::from(reduced.is_zero()) {
        reduced.zeroize();
        return None;
    }

    let bytes = Zeroizing::new(reduced.to_repr().into());
    reduced.zeroize();
    Some(bytes)
}

/// Return whether bytes are a canonical secp256k1 scalar encoding.
///
/// The caller selects whether zero is part of the accepted domain. No
/// reduction or normalization is performed.
pub fn scalar_bytes_are_canonical(bytes: &[u8; 32], allow_zero: bool) -> bool {
    if allow_zero {
        is_scalar_canonical_allow_zero(bytes)
    } else {
        is_scalar_valid(bytes)
    }
}

impl ConstantTimeEq for SecretScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Derive a public point from canonical nonzero secret scalar bytes.
pub fn secret_scalar_public_key(secret_be: &[u8; 32]) -> Result<PublicKey, DomError> {
    let scalar = Zeroizing::new(
        scalar_from_bytes(secret_be)
            .ok_or_else(|| DomError::Invalid("secret scalar is noncanonical".into()))?,
    );
    let compressed = projective_to_compressed(&(ProjectivePoint::GENERATOR * *scalar));
    PublicKey::from_compressed_bytes(&compressed)
}

/// Accumulate `accumulator + coefficient*multiplicand` in constant time.
///
/// The accumulator is replaced only after every input has passed canonical
/// parsing. All byte buffers remain caller-owned and compiler-visibly
/// zeroizing where required by the caller.
pub fn secret_scalar_mul_add_assign(
    accumulator_be: &mut Zeroizing<[u8; 32]>,
    multiplicand_be: &[u8; 32],
    coefficient_be: &[u8; 32],
) -> Result<(), DomError> {
    let accumulator = Zeroizing::new(
        scalar_from_bytes(accumulator_be)
            .ok_or_else(|| DomError::Invalid("accumulator scalar is noncanonical".into()))?,
    );
    let multiplicand = Zeroizing::new(
        scalar_from_bytes(multiplicand_be)
            .ok_or_else(|| DomError::Invalid("multiplicand scalar is noncanonical".into()))?,
    );
    let coefficient = scalar_from_bytes(coefficient_be)
        .ok_or_else(|| DomError::Invalid("scalar coefficient is noncanonical".into()))?;
    let result = Zeroizing::new(*accumulator + coefficient * *multiplicand);
    *accumulator_be = Zeroizing::new(result.to_repr().into());
    Ok(())
}

/// Verify the generic Schnorr relation `zG == A + cX`.
pub fn verify_scalar_response(
    response_be: &[u8; 32],
    commitment: &PublicKey,
    challenge_be: &[u8; 32],
    statement_point: &PublicKey,
) -> Result<bool, DomError> {
    let response = scalar_from_bytes(response_be)
        .ok_or_else(|| DomError::Invalid("response scalar is noncanonical".into()))?;
    if !is_scalar_valid(challenge_be) {
        return Err(DomError::Invalid(
            "challenge scalar is zero or noncanonical".into(),
        ));
    }
    let challenge = scalar_from_bytes(challenge_be)
        .ok_or_else(|| DomError::Invalid("challenge scalar is noncanonical".into()))?;
    let commitment = compressed_to_projective(&commitment.to_compressed_bytes())?;
    let statement = compressed_to_projective(&statement_point.to_compressed_bytes())?;
    Ok(ProjectivePoint::GENERATOR * response == commitment + statement * challenge)
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
    adaptor_secret: &SecretScalar,
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
) -> Result<SecretScalar, DomError> {
    let bytes = scriptless_extract_adaptor_secret_be_bytes(
        final_signature,
        scalar_hat,
        aggregate_nonce_hat,
        adaptor_point,
    )?;
    SecretScalar::from_be_bytes(*bytes)
}

/// Extract and validate the adaptor secret, returning its canonical
/// big-endian bytes.
///
/// The verification is the same one [`scriptless_extract_adaptor_secret`]
/// performs — it is the same code, and that function now delegates here: the
/// final signature's nonce must equal the pre-signature's, both scalars must
/// be canonical, their difference must be nonzero, and `t*G` must equal the
/// committed adaptor point. Only a scalar that passes all of it is returned.
///
/// # Why exporting these bytes is not a leak
///
/// This is the one secret scalar in the protocol that is **public by
/// construction**. It is recovered as `t = s - s_hat` from two signatures
/// that are BOTH already published: the pre-signature the parties exchanged
/// and the final signature observed on chain. Any observer can carry out this
/// same subtraction, so returning the bytes discloses nothing the network
/// does not already hold.
///
/// It is also what an adaptor-signature swap exists to produce. A
/// counterparty leg on another chain is claimed with exactly these 32 bytes;
/// without an export path the DOM leg can prove it recovered the right `t`
/// (by comparing the public point) but cannot hand it over, and the swap
/// cannot complete.
///
/// No other secret gains an export path: [`SecretScalar`] still has no public
/// byte accessor, signing shares and nonces are unaffected, and these bytes
/// are reachable only through a fully verified extraction. The value is
/// returned in a [`Zeroizing`] buffer so it is wiped when the caller drops it.
pub fn scriptless_extract_adaptor_secret_be_bytes(
    final_signature: &SchnorrSignature,
    scalar_hat: &PartialSig,
    aggregate_nonce_hat: &PublicKey,
    adaptor_point: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, DomError> {
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

    let bytes = Zeroizing::new(<[u8; 32]>::from(extracted.to_repr()));
    let secret = SecretScalar::from_be_bytes(*bytes)?;
    if secret.public_key()? != *adaptor_point {
        return Err(DomError::Invalid(
            "extracted scalar does not match the adaptor point".into(),
        ));
    }
    Ok(bytes)
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
        let adaptor_secret = SecretScalar::from_be_bytes(scalar_bytes(13)).expect("t");
        let adaptor_point = adaptor_secret.public_key().expect("T");
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
        assert!(SecretScalar::from_be_bytes([0u8; 32]).is_err());

        let order = secp256k1::constants::CURVE_ORDER;
        assert!(SecretScalar::from_be_bytes(order).is_err());

        let mut order_plus_one = order;
        order_plus_one[31] = order_plus_one[31]
            .checked_add(1)
            .expect("group-order low byte can be incremented");
        assert!(SecretScalar::from_be_bytes(order_plus_one).is_err());
        assert!(SecretScalar::from_be_bytes([0xFF; 32]).is_err());

        let mut high_bit = [0u8; 32];
        high_bit[0] = 0x80;
        assert!(
            SecretScalar::from_be_bytes(high_bit).is_ok(),
            "a high-bit scalar below the group order remains canonical"
        );
    }

    #[test]
    fn wide_scalar_reduction_is_big_endian_and_rejects_zero() {
        assert!(scalar_from_wide_be(&[0u8; 64]).is_none());

        let mut one = [0u8; 64];
        one[63] = 1;
        let reduced_one = scalar_from_wide_be(&one).expect("one remains one");
        assert_eq!(reduced_one.as_ref(), &scalar_bytes(1));

        let order = secp256k1::constants::CURVE_ORDER;
        let mut exact_order = [0u8; 64];
        exact_order[32..].copy_from_slice(&order);
        assert!(scalar_from_wide_be(&exact_order).is_none());

        let mut order_plus_one = exact_order;
        order_plus_one[63] = order_plus_one[63].checked_add(1).expect("order low byte");
        let reduced = scalar_from_wide_be(&order_plus_one).expect("n + 1 reduces to one");
        assert_eq!(reduced.as_ref(), &scalar_bytes(1));

        let mut high_bit = [0u8; 64];
        high_bit[0] = 0x80;
        let high = scalar_from_wide_be(&high_bit).expect("2^511 has a nonzero residue");
        assert_ne!(high.as_ref(), &[0u8; 32]);
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
                        SecretScalar::from_be_bytes(scalar_bytes(adaptor_value)).expect("t");
                    let adaptor_point = adaptor_secret.public_key().expect("T");
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
            let adaptor_secret = SecretScalar::from_be_bytes(scalar_bytes(adaptor_value))
                .expect("canonical adaptor scalar");
            let adaptor_point = adaptor_secret
                .public_key()
                .expect("canonical adaptor point");
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
                extracted.public_key().expect("extracted point"),
                adaptor_point,
                "case {case} extract(adapt(presign)) must recover t"
            );
        }
    }
}
