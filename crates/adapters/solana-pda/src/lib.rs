//! SDK-independent Program Derived Address derivation.

#![forbid(unsafe_code)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use solana_escrow_wire::{NATIVE_VAULT_SEED, STATE_SEED, TOKEN_VAULT_SEED, VAULT_AUTHORITY_SEED};
use solana_types::SolanaPubkey;

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
const MAX_SEEDS: usize = 16;
const MAX_SEED_LEN: usize = 32;

/// PDA derivation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdaError {
    #[error("seed bound exceeded")]
    SeedBounds,
    #[error("derived address is on curve")]
    OnCurve,
    #[error("no viable bump")]
    NoBump,
}

/// Reproduce Solana's `create_program_address` algorithm.
pub fn create_program_address(
    seeds: &[&[u8]],
    program_id: &SolanaPubkey,
) -> Result<SolanaPubkey, PdaError> {
    if seeds.len() > MAX_SEEDS || seeds.iter().any(|seed| seed.len() > MAX_SEED_LEN) {
        return Err(PdaError::SeedBounds);
    }
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(program_id.0);
    hasher.update(PDA_MARKER);
    let bytes: [u8; 32] = hasher.finalize().into();
    if CompressedEdwardsY(bytes).decompress().is_some() {
        return Err(PdaError::OnCurve);
    }
    Ok(SolanaPubkey(bytes))
}

/// Find the highest viable bump, exactly like `find_program_address`.
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &SolanaPubkey,
) -> Result<(SolanaPubkey, u8), PdaError> {
    if seeds.len() >= MAX_SEEDS {
        return Err(PdaError::SeedBounds);
    }
    for bump in (0u8..=255).rev() {
        let bump_seed = [bump];
        let mut all = Vec::with_capacity(seeds.len() + 1);
        all.extend_from_slice(seeds);
        all.push(&bump_seed);
        match create_program_address(&all, program_id) {
            Ok(address) => return Ok((address, bump)),
            Err(PdaError::OnCurve) => {}
            Err(error) => return Err(error),
        }
    }
    Err(PdaError::NoBump)
}

/// All PDAs used by one settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowPdas {
    pub state: SolanaPubkey,
    pub state_bump: u8,
    pub native_vault: SolanaPubkey,
    pub native_vault_bump: u8,
    pub token_vault: SolanaPubkey,
    pub token_vault_bump: u8,
    pub vault_authority: SolanaPubkey,
    pub vault_authority_bump: u8,
}

/// Derive the complete settlement PDA set.
pub fn derive_escrow_pdas(
    program_id: SolanaPubkey,
    settlement_id: [u8; 32],
) -> Result<EscrowPdas, PdaError> {
    let (state, state_bump) = find_program_address(&[STATE_SEED, &settlement_id], &program_id)?;
    let (native_vault, native_vault_bump) =
        find_program_address(&[NATIVE_VAULT_SEED, &state.0], &program_id)?;
    let (token_vault, token_vault_bump) =
        find_program_address(&[TOKEN_VAULT_SEED, &state.0], &program_id)?;
    let (vault_authority, vault_authority_bump) =
        find_program_address(&[VAULT_AUTHORITY_SEED, &state.0], &program_id)?;
    Ok(EscrowPdas {
        state,
        state_bump,
        native_vault,
        native_vault_bump,
        token_vault,
        token_vault_bump,
        vault_authority,
        vault_authority_bump,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_off_curve() {
        let program = SolanaPubkey([7; 32]);
        let a = derive_escrow_pdas(program, [8; 32]).unwrap();
        let b = derive_escrow_pdas(program, [8; 32]).unwrap();
        assert_eq!(a, b);
        assert!(CompressedEdwardsY(a.state.0).decompress().is_none());
    }
}
