// Allow missing docs during development
#![allow(missing_docs)]
//! Pedersen commitments over secp256k1 — full arithmetic implementation.

use dom_core::DomError;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{elliptic_curve::PrimeField, AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn affine_from_encoded(encoded: &EncodedPoint) -> Option<AffinePoint> {
    let ct = AffinePoint::from_encoded_point(encoded);
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    let arr: &[u8; 32] = bytes.try_into().ok()?;
    let fb = k256::FieldBytes::from(*arr);
    let ct = Scalar::from_repr(fb);
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

fn h_point() -> ProjectivePoint {
    let h_bytes = crate::h_generator::h_compressed()
        .expect("H generator not finalized — run: cargo test -p dom-crypto print_h_generator");
    let encoded =
        EncodedPoint::from_bytes(h_bytes).expect("h_compressed() guarantees valid encoding");
    let affine =
        affine_from_encoded(&encoded).expect("h_compressed() guarantees valid curve point");
    ProjectivePoint::from(affine)
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Commitment(pub(crate) [u8; 33]);

impl Commitment {
    pub fn commit(value: u64, blinding: &BlindingFactor) -> Self {
        let h = h_point();
        let g = ProjectivePoint::GENERATOR;
        let v_scalar = Scalar::from(value);
        let vh = h * v_scalar;
        let r_scalar =
            scalar_from_bytes(blinding.as_bytes()).expect("blinding factor already validated");
        let rg = g * r_scalar;
        let c = vh + rg;
        let affine: AffinePoint = c.into();
        let encoded = EncodedPoint::from(affine).compress();
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        Self(bytes)
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != 33 {
            return Err(DomError::Malformed(format!(
                "commitment must be 33 bytes, got {}",
                bytes.len()
            )));
        }
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|_| DomError::Invalid("commitment: invalid SEC1 encoding".into()))?;
        if affine_from_encoded(&encoded).is_none() {
            return Err(DomError::Invalid(
                "commitment: point not on secp256k1 curve".into(),
            ));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub fn add(&self, other: &Self) -> Result<Self, DomError> {
        let a = self.to_projective()?;
        let b = other.to_projective()?;
        let sum: AffinePoint = (a + b).into();
        let encoded = EncodedPoint::from(sum).compress();
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        Ok(Self(bytes))
    }

    pub fn sub(&self, other: &Self) -> Result<Self, DomError> {
        let a = self.to_projective()?;
        let b = other.to_projective()?;
        let diff: AffinePoint = (a - b).into();
        let encoded = EncodedPoint::from(diff).compress();
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        Ok(Self(bytes))
    }

    pub fn verify(&self, value: u64, blinding: &BlindingFactor) -> bool {
        let expected = Self::commit(value, blinding);
        bool::from(self.0.ct_eq(&expected.0))
    }

    fn to_projective(&self) -> Result<ProjectivePoint, DomError> {
        let encoded = EncodedPoint::from_bytes(self.0)
            .map_err(|_| DomError::Invalid("invalid commitment encoding".into()))?;
        let affine = affine_from_encoded(&encoded)
            .ok_or_else(|| DomError::Invalid("commitment point not on curve".into()))?;
        Ok(ProjectivePoint::from(affine))
    }
}

impl std::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Commitment({})", hex::encode(self.0))
    }
}

#[derive(Debug, Clone)]
pub enum BlindingFactorOrZero {
    NonZero(BlindingFactor),
    Zero,
}

impl BlindingFactorOrZero {
    pub fn require_nonzero(self) -> Result<BlindingFactor, DomError> {
        match self {
            Self::NonZero(bf) => Ok(bf),
            Self::Zero => Err(DomError::Invalid(
                "expected non-zero blinding factor".into(),
            )),
        }
    }

    pub fn to_excess_point(&self) -> ProjectivePoint {
        match self {
            Self::NonZero(bf) => {
                let s = scalar_from_bytes(&bf.0).expect("NonZero BlindingFactor is always valid");
                ProjectivePoint::GENERATOR * s
            }
            Self::Zero => ProjectivePoint::IDENTITY,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlindingFactor([u8; 32]);

impl BlindingFactor {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, DomError> {
        let s = scalar_from_bytes(&bytes);
        match s {
            None => Err(DomError::Invalid("blinding factor out of range".into())),
            Some(s) if s.is_zero().into() => {
                Err(DomError::Invalid("blinding factor is zero".into()))
            }
            _ => Ok(Self(bytes)),
        }
    }

    pub fn random() -> Self {
        use rand::RngCore; // já importado via workspace
        let mut bytes = [0u8; 32];
        loop {
            rand::thread_rng().fill_bytes(&mut bytes);
            if let Ok(bf) = Self::from_bytes(bytes) {
                return bf;
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn add(&self, other: &Self) -> Result<Self, DomError> {
        let a = scalar_from_bytes(&self.0)
            .ok_or_else(|| DomError::Invalid("invalid blinding factor a".into()))?;
        let b = scalar_from_bytes(&other.0)
            .ok_or_else(|| DomError::Invalid("invalid blinding factor b".into()))?;
        let sum = a + b;
        if sum.is_zero().into() {
            return Err(DomError::Invalid("blinding factor sum is zero".into()));
        }
        let bytes: [u8; 32] = sum.to_repr().into();
        Ok(Self(bytes))
    }

    pub fn sub(&self, other: &Self) -> Result<BlindingFactorOrZero, DomError> {
        let a = scalar_from_bytes(&self.0)
            .ok_or_else(|| DomError::Invalid("invalid blinding factor a".into()))?;
        let b = scalar_from_bytes(&other.0)
            .ok_or_else(|| DomError::Invalid("invalid blinding factor b".into()))?;
        let diff = a - b;
        if diff.is_zero().into() {
            Ok(BlindingFactorOrZero::Zero)
        } else {
            let bytes: [u8; 32] = diff.to_repr().into();
            Ok(BlindingFactorOrZero::NonZero(Self(bytes)))
        }
    }

    pub fn sub_nonzero(&self, other: &Self) -> Result<Self, DomError> {
        match self.sub(other)? {
            BlindingFactorOrZero::NonZero(bf) => Ok(bf),
            BlindingFactorOrZero::Zero => Err(DomError::Invalid(
                "blinding factor difference is zero".into(),
            )),
        }
    }
}

impl std::fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlindingFactor([REDACTED])")
    }
}

pub fn verify_balance_equation(
    output_commits: &[Commitment],
    input_commits: &[Commitment],
    kernel_excesses: &[Commitment],
    offset: &[u8; 32],
    total_fee: u64,
) -> Result<bool, DomError> {
    let sum_outputs = sum_projective(output_commits)?;
    let sum_inputs = sum_projective(input_commits)?;
    let mut lhs = sum_outputs - sum_inputs;

    if total_fee > 0 {
        let fee_scalar = Scalar::from(total_fee);
        lhs += h_point() * fee_scalar;
    }

    let mut rhs = sum_projective(kernel_excesses)?;
    if offset != &[0u8; 32] {
        let offset_scalar = scalar_from_bytes(offset)
            .ok_or_else(|| DomError::Invalid("invalid offset scalar".into()))?;
        rhs += ProjectivePoint::GENERATOR * offset_scalar;
    }

    Ok(lhs == rhs)
}

fn sum_projective(commits: &[Commitment]) -> Result<ProjectivePoint, DomError> {
    let mut acc = ProjectivePoint::IDENTITY;
    for c in commits {
        acc += c.to_projective()?;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_bf() -> BlindingFactor {
        BlindingFactor::random()
    }

    #[test]
    fn commitment_deterministic() {
        let bf = BlindingFactor::from_bytes([1u8; 32]).unwrap();
        let c1 = Commitment::commit(100, &bf);
        let c2 = Commitment::commit(100, &bf);
        assert_eq!(c1, c2);
    }

    #[test]
    fn different_values_different_commitments() {
        let bf = BlindingFactor::from_bytes([1u8; 32]).unwrap();
        let c1 = Commitment::commit(100, &bf);
        let c2 = Commitment::commit(101, &bf);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_blindings_different_commitments() {
        let bf1 = BlindingFactor::from_bytes([1u8; 32]).unwrap();
        let bf2 = BlindingFactor::from_bytes([2u8; 32]).unwrap();
        let c1 = Commitment::commit(100, &bf1);
        let c2 = Commitment::commit(100, &bf2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_verify() {
        let bf = rand_bf();
        let c = Commitment::commit(369, &bf);
        assert!(c.verify(369, &bf));
        assert!(!c.verify(370, &bf));
    }

    #[test]
    fn homomorphic_addition() {
        let bf1 = rand_bf();
        let bf2 = rand_bf();
        let c1 = Commitment::commit(10, &bf1);
        let c2 = Commitment::commit(20, &bf2);
        let sum = c1.add(&c2).unwrap();
        let bf_sum = bf1.add(&bf2).unwrap();
        let expected = Commitment::commit(30, &bf_sum);
        assert_eq!(sum, expected);
    }

    #[test]
    fn homomorphic_subtraction() {
        let bf1 = rand_bf();
        let bf2 = rand_bf();
        let c1 = Commitment::commit(30, &bf1);
        let c2 = Commitment::commit(20, &bf2);
        let diff = c1.sub(&c2).unwrap();
        let bf_diff = bf1.sub(&bf2).unwrap().require_nonzero().unwrap();
        let expected = Commitment::commit(10, &bf_diff);
        assert_eq!(diff, expected);
    }

    #[test]
    fn zero_blinding_rejected() {
        assert!(BlindingFactor::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn commitment_roundtrip_bytes() {
        let bf = rand_bf();
        let c = Commitment::commit(1000, &bf);
        let bytes = *c.as_bytes();
        let c2 = Commitment::from_compressed_bytes(&bytes).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn balance_equation_simple_transaction() {
        let r_in = rand_bf();
        let r_out1 = rand_bf();
        let r_out2 = rand_bf();
        let r_excess = {
            let sum_out = r_out1.add(&r_out2).unwrap();
            sum_out.sub(&r_in).unwrap().require_nonzero().unwrap()
        };
        let input = Commitment::commit(50, &r_in);
        let out1 = Commitment::commit(30, &r_out1);
        let out2 = Commitment::commit(19, &r_out2);
        let kernel_excess = Commitment::commit(0, &r_excess);
        let valid =
            verify_balance_equation(&[out1, out2], &[input], &[kernel_excess], &[0u8; 32], 1)
                .unwrap();
        assert!(valid);
    }

    #[test]
    fn balance_equation_no_fee() {
        let r_in = rand_bf();
        let r_out = rand_bf();
        let r_excess = r_out.sub(&r_in).unwrap().require_nonzero().unwrap();
        let input = Commitment::commit(10, &r_in);
        let output = Commitment::commit(10, &r_out);
        let excess = Commitment::commit(0, &r_excess);
        let valid = verify_balance_equation(&[output], &[input], &[excess], &[0u8; 32], 0).unwrap();
        assert!(valid);
    }

    #[test]
    fn balance_equation_with_offset() {
        let r_in = rand_bf();
        let r_out = rand_bf();
        let offset_r = BlindingFactor::from_bytes([3u8; 32]).unwrap();
        let r_excess = r_out
            .sub(&r_in)
            .unwrap()
            .require_nonzero()
            .unwrap()
            .sub_nonzero(&offset_r)
            .unwrap();
        let input = Commitment::commit(10, &r_in);
        let output = Commitment::commit(10, &r_out);
        let excess = Commitment::commit(0, &r_excess);
        let offset_bytes = *offset_r.as_bytes();
        let valid =
            verify_balance_equation(&[output], &[input], &[excess], &offset_bytes, 0).unwrap();
        assert!(valid);
    }

    #[test]
    fn balance_equation_tampered_fails() {
        let r_in = rand_bf();
        let r_out = rand_bf();
        let r_excess = r_in.sub(&r_out).unwrap().require_nonzero().unwrap();
        let input = Commitment::commit(10, &r_in);
        let _output = Commitment::commit(10, &r_out);
        let kernel_excess = Commitment::commit(0, &r_excess);
        let wrong_r = rand_bf();
        let wrong_output = Commitment::commit(11, &wrong_r);
        let valid =
            verify_balance_equation(&[wrong_output], &[input], &[kernel_excess], &[0u8; 32], 0)
                .unwrap();
        assert!(!valid);
    }
}
