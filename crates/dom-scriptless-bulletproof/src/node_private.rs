//! Three helpers the node keeps `pub(crate)` inside `dom-crypto`.
//!
//! Transcribed byte for byte from the mainnet v2 release line, visibility
//! widened and nothing else changed. `backend::conformance` pins the whole
//! transcription to the node behaviourally.

use dom_core::DomError;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::RANGE_PROOF_SIZE;
use dom_scriptless_primitives::curve::scalar_from_bytes;
use k256::elliptic_curve::PrimeField;

/// `value · H_DOM`, with no blinding term.
///
/// The node computes this with a crate-private generator handle. Here it is
/// obtained from the node's own commitment constructor instead of from a
/// second generator: `commit(v, b) - commit(0, b)` cancels `b·G` for any `b`,
/// leaving exactly `v·H_DOM` as the node itself would compute it.
fn commit_unblinded(value: u64) -> Result<Commitment, DomError> {
    let blinding = BlindingFactor::from_bytes({
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        bytes
    })?;
    Commitment::commit(value, &blinding).sub(&Commitment::commit(0, &blinding))
}


pub fn derive_complement_commitment(
    commitment: &Commitment,
    max_value: u64,
) -> Result<Commitment, DomError> {
    let max_commit = commit_unblinded(max_value)?;
    max_commit.sub(commitment)
}
pub fn negate_blinding(blinding: &[u8; 32]) -> Result<[u8; 32], DomError> {
    let scalar = scalar_from_bytes(blinding)
        .ok_or_else(|| DomError::Invalid("invalid blinding factor".into()))?;
    let neg = -scalar;
    Ok(neg.to_repr().into())
}
/// Return whether a serialized proof has the one canonical protocol length.
pub const fn range_proof_length_is_canonical(length: usize) -> bool {
    length == RANGE_PROOF_SIZE
}
