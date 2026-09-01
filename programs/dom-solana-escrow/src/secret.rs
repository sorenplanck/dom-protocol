//! On-chain verification of the shared 252-bit witness.

use solana_curve25519::{
    edwards::{multiply_edwards, PodEdwardsPoint},
    scalar::PodScalar,
};

use crate::error::EscrowProgramError;

// Canonical compressed Ed25519 basepoint: 0x58 followed by 31 bytes 0x66.
const ED25519_BASEPOINT: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Verify `secret * G_ed25519 == expected`, using Solana's curve syscall.
pub fn verify_shared_secret(
    secret_big_endian: [u8; 32],
    expected: [u8; 32],
) -> Result<(), EscrowProgramError> {
    if secret_big_endian == [0; 32] || expected == [0; 32] {
        return Err(EscrowProgramError::InvalidSecret);
    }
    let mut little_endian = secret_big_endian;
    little_endian.reverse();

    // The off-chain DLEQ proves equality over a 252-bit integer. Enforce the
    // same domain before calling a syscall which otherwise interprets scalar
    // bytes modulo the group order.
    if little_endian[31] & 0xf0 != 0 {
        return Err(EscrowProgramError::InvalidSecret);
    }

    let point = multiply_edwards(
        &PodScalar(little_endian),
        &PodEdwardsPoint(ED25519_BASEPOINT),
    )
    .ok_or(EscrowProgramError::InvalidSecret)?;
    if point.0 != expected {
        return Err(EscrowProgramError::InvalidSecret);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_secret_is_rejected() {
        assert_eq!(
            verify_shared_secret([0; 32], [1; 32]),
            Err(EscrowProgramError::InvalidSecret)
        );
    }
}
