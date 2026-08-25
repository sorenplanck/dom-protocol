//! Opaque signing-share ownership for DOM Scriptless Contracts.

use crate::{AdaptorError, Result};
use dom_crypto::{PublicKey, blake2b_256_tagged};
use dom_scriptless_primitives::{scalar_bytes_are_canonical, secret_scalar_mul_add_assign, secret_scalar_public_key};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Domain tag for the decoy-contribution seed keyed by the signing share.
const DECOY_SEED_TAG_V1: &str = crate::DomainTag::DecoyShareSeed.as_str();

/// Canonical signing share with no raw-byte export.
///
/// The type deliberately implements no clone, copy, debug, display, equality,
/// ordering, or generic serialization. Its bytes are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningShareV1 {
    bytes: [u8; 32],
    #[zeroize(skip)]
    public_key: PublicKey,
}

impl SigningShareV1 {
    /// Parse a canonical nonzero big-endian signing share.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if !scalar_bytes_are_canonical(&bytes, false) {
            return Err(AdaptorError::InvalidContext(
                "signing share must be a canonical nonzero scalar",
            ));
        }
        let public_key = secret_scalar_public_key(&bytes)?;
        Ok(Self {
            bytes: *bytes,
            public_key,
        })
    }

    /// Return the corresponding canonical public key.
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Derive a decoy-contribution seed keyed by the private share.
    ///
    /// The share's public key is public, so a decoy stream keyed only on it
    /// would be predictable by anyone. This folds the secret bytes in through
    /// a domain-separated keyed digest, returning a fresh 32-byte seed and
    /// never the share itself. The returned value is caller-zeroized.
    pub fn decoy_seed_v1(&self, context: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut input = Zeroizing::new(Vec::with_capacity(32 + context.len()));
        input.extend_from_slice(&self.bytes);
        input.extend_from_slice(context);
        Zeroizing::new(*blake2b_256_tagged(DECOY_SEED_TAG_V1, &input).as_bytes())
    }

    #[cfg(test)]
    pub(crate) fn zeroizing_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bytes)
    }

    pub(crate) const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Compose one participant's shared-output blinding share with that same
/// participant's wallet-side funding excess contribution.
///
/// This is the narrow scalar composition required by the funding balance
/// equation: `x_i = r_i + e_i (mod n)`, where `r_i` is this participant's
/// collaborative-output share and `e_i` is its ordinary wallet contribution
/// from inputs, change and offset allocation. Both inputs remain opaque and
/// borrowed; the result is a new zeroizing [`SigningShareV1`] and no scalar
/// bytes are exported.
///
/// Callers must never pass shares from different participants. In particular,
/// this function is not an authorization to reconstruct the aggregate shared
/// blinding `r_A + r_B`, which the Master Specification forbids. A zero sum is
/// rejected because it has no canonical signing public key.
pub fn compose_local_funding_signing_share_v1(
    shared_output_blinding_share: &SigningShareV1,
    wallet_excess_contribution: &SigningShareV1,
) -> Result<SigningShareV1> {
    let mut combined = Zeroizing::new(*shared_output_blinding_share.as_be_bytes());
    let mut one = Zeroizing::new([0u8; 32]);
    one[31] = 1;
    secret_scalar_mul_add_assign(
        &mut combined,
        wallet_excess_contribution.as_be_bytes(),
        &one,
    )?;
    SigningShareV1::from_be_bytes(*combined)
}

/// Compose one participant's kernel-signing share for an exact spend of the
/// shared output.
///
/// For the claim/refund templates accepted by the V1 lifecycle builder, the
/// only input is the shared output. The wallet-side contribution is therefore
/// `e_i = sum(payout_blindings_i) - offset_i`, while the participant retains
/// only its own shared-output share `r_i`. This function performs the remaining
/// authority-side operation `y_i = e_i - r_i (mod n)` without exporting either
/// secret scalar or ever reconstructing `r_A + r_B`.
///
/// Both inputs are borrowed and remain opaque. The returned share is a new
/// zeroizing value. A zero result is rejected because it cannot key a canonical
/// DOM kernel signature.
pub fn compose_local_shared_output_spend_signing_share_v1(
    wallet_payout_excess_contribution: &SigningShareV1,
    shared_output_blinding_share: &SigningShareV1,
) -> Result<SigningShareV1> {
    // -1 mod the secp256k1 group order. Using the pinned secret-scalar
    // primitive keeps all arithmetic in the authoritative crypto boundary.
    const NEGATIVE_ONE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];
    let mut combined = Zeroizing::new(*wallet_payout_excess_contribution.as_be_bytes());
    secret_scalar_mul_add_assign(
        &mut combined,
        shared_output_blinding_share.as_be_bytes(),
        &NEGATIVE_ONE,
    )?;
    SigningShareV1::from_be_bytes(*combined)
}

/// Aggregate public per-participant transaction-offset contributions.
///
/// Every contribution must be a canonical nonzero scalar. The aggregate is
/// computed modulo the secp256k1 group order through DOM's pinned scalar
/// primitive and may canonically be zero, which is explicitly valid for
/// `Transaction::offset` and its balance verifier. An empty participant set is
/// rejected so a caller cannot mistake absence of contributions for a valid
/// aggregate.
pub fn aggregate_transaction_offset_contributions_v1(
    contributions: &[[u8; 32]],
) -> Result<[u8; 32]> {
    if contributions.is_empty() {
        return Err(AdaptorError::InvalidContext(
            "transaction offset contribution set is empty",
        ));
    }
    let mut aggregate = Zeroizing::new([0u8; 32]);
    let mut one = Zeroizing::new([0u8; 32]);
    one[31] = 1;
    for contribution in contributions {
        if !scalar_bytes_are_canonical(contribution, false) {
            return Err(AdaptorError::InvalidContext(
                "transaction offset contribution must be a canonical nonzero scalar",
            ));
        }
        secret_scalar_mul_add_assign(&mut aggregate, contribution, &one)?;
    }
    Ok(*aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_scriptless_primitives::scriptless_add_public_points;

    fn small(value: u8) -> SigningShareV1 {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes).expect("small canonical share")
    }

    #[test]
    fn constructor_rejects_every_fallible_scalar_boundary() {
        const GROUP_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(SigningShareV1::from_be_bytes([0u8; 32]).is_err());
        assert!(SigningShareV1::from_be_bytes([0xff; 32]).is_err());
        assert!(SigningShareV1::from_be_bytes(GROUP_ORDER).is_err());
    }

    #[test]
    fn local_funding_composition_is_opaque_and_matches_point_addition() {
        let shared = small(3);
        let wallet = small(5);
        let expected = scriptless_add_public_points(&[
            shared.public_key().clone(),
            wallet.public_key().clone(),
        ])
        .expect("public sum");

        let combined = compose_local_funding_signing_share_v1(&shared, &wallet)
            .expect("nonzero local funding share");
        assert_eq!(combined.public_key(), &expected);
        // Borrowing leaves both independently persisted source shares usable.
        assert_ne!(shared.public_key(), combined.public_key());
        assert_ne!(wallet.public_key(), combined.public_key());
    }

    #[test]
    fn local_funding_composition_reduces_mod_order_and_rejects_zero() {
        const ORDER_MINUS_ONE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ];
        let maximum = SigningShareV1::from_be_bytes(ORDER_MINUS_ONE).expect("n-1");
        assert!(compose_local_funding_signing_share_v1(&maximum, &small(1)).is_err());

        let wrapped = compose_local_funding_signing_share_v1(&maximum, &small(2))
            .expect("n-1 + 2 == 1 mod n");
        assert_eq!(wrapped.public_key(), small(1).public_key());
    }

    #[test]
    fn local_shared_output_spend_composition_subtracts_without_export() {
        let wallet_payout = small(8);
        let shared = small(3);
        let spend = compose_local_shared_output_spend_signing_share_v1(&wallet_payout, &shared)
            .expect("8 - 3 == 5");
        assert_eq!(spend.public_key(), small(5).public_key());
        assert!(compose_local_shared_output_spend_signing_share_v1(&shared, &shared).is_err());
    }

    #[test]
    fn transaction_offset_aggregation_is_canonical_and_permits_zero_sum() {
        const ORDER_MINUS_ONE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ];
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            aggregate_transaction_offset_contributions_v1(&[one, ORDER_MINUS_ONE])
                .expect("1 + (n - 1) == 0"),
            [0u8; 32]
        );
        assert!(aggregate_transaction_offset_contributions_v1(&[]).is_err());
        assert!(aggregate_transaction_offset_contributions_v1(&[[0u8; 32]]).is_err());
        assert!(aggregate_transaction_offset_contributions_v1(&[[0xff; 32]]).is_err());
    }
}
