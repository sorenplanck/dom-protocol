//! Program error taxonomy.

use solana_program::program_error::ProgramError;

/// Stable custom program errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EscrowProgramError {
    InvalidInstruction = 1,
    InvalidAccounts = 2,
    MissingSignature = 3,
    InvalidOwner = 4,
    InvalidPda = 5,
    InvalidState = 6,
    InvalidAsset = 7,
    InvalidAmount = 8,
    InvalidSecret = 9,
    TimelockNotReached = 10,
    Arithmetic = 11,
    AccountBorrow = 12,
    AlreadyInitialized = 13,
    TokenProgramRejected = 14,
    TokenAccountRejected = 15,
    ClockUnavailable = 16,
    RentUnavailable = 17,
}

impl From<EscrowProgramError> for ProgramError {
    fn from(value: EscrowProgramError) -> Self {
        ProgramError::Custom(value as u32)
    }
}
