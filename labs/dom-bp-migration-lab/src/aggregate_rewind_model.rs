//! Scalar-only algebra model for the DOM two-commitment Bulletproof.
//!
//! This is research code, not a proof implementation.  It models the exact
//! blinding term emitted by Grin secp256k1-zkp 0.7.15 and deliberately keeps
//! all recovery decisions fail-closed.

use dom_crypto::{pedersen::Commitment, BlindingFactor};
use k256::{elliptic_curve::group::ff::PrimeField, Scalar};
use zeroize::Zeroize;

pub const L1B_SEED: u64 = 0xA661_E6A7_EE51_0001;
pub const L1B_CASES: usize = 10_000;
pub const METADATA_LEN: usize = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalMetadata(pub [u8; METADATA_LEN]);

impl CanonicalMetadata {
    /// Test-only canonical layout: version, network, account BE, branch,
    /// index BE, then a nine-byte binding-digest truncation.
    pub fn test_vector() -> Self {
        Self([
            1, 42, 0, 0, 0, 7, 3, 0, 0, 0, 9, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29,
        ])
    }

    /// Packs `0x000000 || metadata || value_be` exactly as the single-commit
    /// backend convention at rangeproof_impl.h:529-538.
    pub fn pack_with_value(&self, value: u64) -> [u8; 32] {
        let mut packed = [0_u8; 32];
        packed[4..24].copy_from_slice(&self.0);
        packed[24..32].copy_from_slice(&value.to_be_bytes());
        packed
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentPair {
    pub first_value: u64,
    pub first_blind: Scalar,
    pub second_value: u64,
    pub second_blind: Scalar,
}

impl CommitmentPair {
    pub fn dom(value: u64, max_value: u64, blind: Scalar) -> Option<Self> {
        let complement = max_value.checked_sub(value)?;
        Some(Self {
            first_value: value,
            first_blind: blind,
            second_value: complement,
            second_blind: -blind,
        })
    }

    pub fn is_dom_complement(&self, max_value: u64) -> bool {
        self.first_value
            .checked_add(self.second_value)
            .is_some_and(|sum| sum == max_value)
            && self.second_blind == -self.first_blind
    }

    /// Recomputes the actual SEC1 commitments under H_DOM.  This is used only
    /// as a laboratory cross-check after scalar recovery.
    pub fn sec1_commitments(&self) -> Result<[[u8; 33]; 2], RecoveryError> {
        let first = BlindingFactor::from_bytes(self.first_blind.to_bytes().into())
            .map_err(|_| RecoveryError::CommitmentMismatch)?;
        let second = BlindingFactor::from_bytes(self.second_blind.to_bytes().into())
            .map_err(|_| RecoveryError::CommitmentMismatch)?;
        Ok([
            *Commitment::commit(self.first_value, &first).as_bytes(),
            *Commitment::commit(self.second_value, &second).as_bytes(),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct AggregationChallenges {
    pub z: Scalar,
    pub x: Scalar,
}

impl AggregationChallenges {
    pub fn valid(&self) -> bool {
        !bool::from(self.z.is_zero()) && !bool::from(self.x.is_zero())
    }
}

#[derive(Clone, Debug)]
pub struct NonceScalars {
    pub alpha: Scalar,
    pub rho: Scalar,
    pub tau1: Scalar,
    pub tau2: Scalar,
}

impl Zeroize for NonceScalars {
    fn zeroize(&mut self) {
        self.alpha = Scalar::ZERO;
        self.rho = Scalar::ZERO;
        self.tau1 = Scalar::ZERO;
        self.tau2 = Scalar::ZERO;
    }
}

#[derive(Clone, Debug)]
pub struct AggregateProofHeader {
    /// Rangeproof bytes 0..32, represented as a scalar: the backend stores
    /// `-taux` at rangeproof_impl.h:693.
    pub serialized_taux: Scalar,
    /// Rangeproof bytes 32..64, represented as a scalar: `-mu`.
    pub serialized_mu: Scalar,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidChallenge,
    MissingValueAndMetadataEncoding,
    NonInvertibleBlindCoefficient,
    CommitmentMismatch,
    MetadataMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryResult {
    pub value: u64,
    pub blind: Scalar,
    pub metadata: CanonicalMetadata,
}

/// The exact aggregate coefficient from the live `for (i=0; i<n_commits;
/// i++)` loop: `z^2` for blind[0], then `z^3` for blind[1].
pub fn dom_blind_coefficient(z: Scalar) -> Scalar {
    let z_squared = z.square();
    z_squared * (Scalar::ONE - z)
}

pub fn aggregate_taux(
    pair: &CommitmentPair,
    nonces: &NonceScalars,
    challenges: &AggregationChallenges,
) -> Scalar {
    let mut z_power = challenges.z.square();
    let mut result = nonces.tau1 * challenges.x + nonces.tau2 * challenges.x.square();
    for blind in [pair.first_blind, pair.second_blind] {
        result += z_power * blind;
        z_power *= challenges.z;
    }
    result
}

/// Header for the live unmodified aggregate prover.  Its alpha has no packed
/// value/message because the C code restricts that branch to `n_commits == 1`.
pub fn current_aggregate_header(
    pair: &CommitmentPair,
    nonces: &NonceScalars,
    challenges: &AggregationChallenges,
) -> AggregateProofHeader {
    let taux = aggregate_taux(pair, nonces, challenges);
    AggregateProofHeader {
        serialized_taux: -taux,
        serialized_mu: -(nonces.rho * challenges.x + nonces.alpha),
    }
}

/// Header for the narrow experimental alteration considered in L1-B: use the
/// existing alpha packing branch for `n_commits == 2`.  This changes no byte
/// count, parser, or verifier equation, but it is not production code.
pub fn packed_aggregate_header(
    pair: &CommitmentPair,
    nonces: &NonceScalars,
    challenges: &AggregationChallenges,
    metadata: &CanonicalMetadata,
) -> AggregateProofHeader {
    let packed = scalar_from_canonical_bytes(metadata.pack_with_value(pair.first_value));
    let taux = aggregate_taux(pair, nonces, challenges);
    AggregateProofHeader {
        serialized_taux: -taux,
        serialized_mu: -(nonces.rho * challenges.x + nonces.alpha - packed),
    }
}

/// Reconstructs the packed value/message from the alpha/mu relation.  The
/// caller must already have performed full Bulletproof verification; this
/// model intentionally cannot turn this header-only operation into a verifier.
pub fn recover_packed_value_metadata(
    header: &AggregateProofHeader,
    nonces: &NonceScalars,
    challenges: &AggregationChallenges,
) -> Result<(u64, CanonicalMetadata), RecoveryError> {
    if !challenges.valid() {
        return Err(RecoveryError::InvalidChallenge);
    }
    let packed = header.serialized_mu + nonces.rho * challenges.x + nonces.alpha;
    let bytes = packed.to_bytes();
    if bytes[..4] != [0_u8; 4] {
        return Err(RecoveryError::MissingValueAndMetadataEncoding);
    }
    let mut metadata = [0_u8; METADATA_LEN];
    metadata.copy_from_slice(&bytes[4..24]);
    let mut value_bytes = [0_u8; 8];
    value_bytes.copy_from_slice(&bytes[24..32]);
    Ok((u64::from_be_bytes(value_bytes), CanonicalMetadata(metadata)))
}

/// Recovers r from the two-commitment taux term.  It is defined only when
/// `z^2 * (1-z)` is invertible.  `z == 1` is accepted by the live verifier's
/// scalar checks, so the fail-closed branch is security-relevant.
pub fn recover_first_blind(
    header: &AggregateProofHeader,
    nonces: &NonceScalars,
    challenges: &AggregationChallenges,
) -> Result<Scalar, RecoveryError> {
    if !challenges.valid() {
        return Err(RecoveryError::InvalidChallenge);
    }
    let coefficient = dom_blind_coefficient(challenges.z);
    let inverse = Option::<Scalar>::from(coefficient.invert())
        .ok_or(RecoveryError::NonInvertibleBlindCoefficient)?;
    let masks = nonces.tau1 * challenges.x + nonces.tau2 * challenges.x.square();
    Ok(-(header.serialized_taux + masks) * inverse)
}

pub fn recover_packed_aggregate(
    header: &AggregateProofHeader,
    nonces: &NonceScalars,
    challenges: &AggregationChallenges,
    pair: &CommitmentPair,
    max_value: u64,
    expected_metadata: &CanonicalMetadata,
) -> Result<RecoveryResult, RecoveryError> {
    let (value, metadata) = recover_packed_value_metadata(header, nonces, challenges)?;
    let blind = recover_first_blind(header, nonces, challenges)?;
    let recomputed =
        CommitmentPair::dom(value, max_value, blind).ok_or(RecoveryError::CommitmentMismatch)?;
    if &recomputed != pair || recomputed.sec1_commitments()? != pair.sec1_commitments()? {
        return Err(RecoveryError::CommitmentMismatch);
    }
    if &metadata != expected_metadata {
        return Err(RecoveryError::MetadataMismatch);
    }
    Ok(RecoveryResult {
        value,
        blind,
        metadata,
    })
}

pub fn scalar_from_u64(value: u64) -> Scalar {
    Scalar::from(value)
}

pub fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(bytes.into())).expect("canonical packed scalar")
}

/// Explicitly erases scalar test witness material once each model case ends.
pub fn zeroize_nonces(nonces: &mut NonceScalars) {
    nonces.zeroize();
}
