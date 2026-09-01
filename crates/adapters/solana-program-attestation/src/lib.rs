//! Finalized attestation of an immutable upgradeable Solana program.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use solana_rpc::SolanaRpc;
use solana_rpc_pool::{QuorumError, SolanaRpcPool};
use solana_types::{Commitment, SolanaPubkey, BPF_LOADER_UPGRADEABLE_ID};

pub const PROGRAM_METADATA_LEN: usize = 36;
pub const PROGRAM_DATA_METADATA_LEN: usize = 45;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramAttestation {
    pub program_id: SolanaPubkey,
    pub program_data_address: SolanaPubkey,
    pub deployment_slot: u64,
    pub code_hash: [u8; 32],
    pub observed_context_slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("RPC quorum failed")]
    Quorum,
    #[error("program account is not a valid upgradeable-loader program")]
    InvalidProgram,
    #[error("program still has an upgrade authority")]
    UpgradeAuthorityPresent,
    #[error("program code hash differs from frozen profile")]
    CodeHashMismatch,
}

pub fn code_hash(code: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-INTEROP/SOLANA-PROGRAM-DATA/V1\0");
    hasher.update((code.len() as u64).to_be_bytes());
    hasher.update(code);
    hasher.finalize().into()
}

pub fn attest_immutable_program<R: SolanaRpc>(
    pool: &SolanaRpcPool<R>,
    program_id: SolanaPubkey,
    expected_code_hash: [u8; 32],
) -> Result<ProgramAttestation, AttestationError> {
    let program = pool
        .account(program_id, Commitment::Finalized)
        .map_err(|_| AttestationError::Quorum)?
        .ok_or(AttestationError::InvalidProgram)?;
    if !program.executable
        || program.owner != BPF_LOADER_UPGRADEABLE_ID
        || program.data.len() < PROGRAM_METADATA_LEN
        || u32::from_le_bytes(
            program.data[..4]
                .try_into()
                .map_err(|_| AttestationError::InvalidProgram)?,
        ) != 2
    {
        return Err(AttestationError::InvalidProgram);
    }
    let mut address = [0u8; 32];
    address.copy_from_slice(&program.data[4..36]);
    let program_data_address = SolanaPubkey(address);
    let program_data = pool
        .account(program_data_address, Commitment::Finalized)
        .map_err(|_| AttestationError::Quorum)?
        .ok_or(AttestationError::InvalidProgram)?;
    if program_data.owner != BPF_LOADER_UPGRADEABLE_ID
        || program_data.executable
        || program_data.data.len() < PROGRAM_DATA_METADATA_LEN
        || u32::from_le_bytes(
            program_data.data[..4]
                .try_into()
                .map_err(|_| AttestationError::InvalidProgram)?,
        ) != 3
    {
        return Err(AttestationError::InvalidProgram);
    }
    let deployment_slot = u64::from_le_bytes(
        program_data.data[4..12]
            .try_into()
            .map_err(|_| AttestationError::InvalidProgram)?,
    );
    // bincode Option<Pubkey>: 0=None, 1=Some followed by 32 bytes. The
    // upgradeable loader reserves the full 45-byte metadata region.
    if program_data.data[12] != 0 {
        return Err(AttestationError::UpgradeAuthorityPresent);
    }
    if program_data.data[13..PROGRAM_DATA_METADATA_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(AttestationError::InvalidProgram);
    }
    let actual = code_hash(&program_data.data[PROGRAM_DATA_METADATA_LEN..]);
    if expected_code_hash == [0; 32] || actual != expected_code_hash {
        return Err(AttestationError::CodeHashMismatch);
    }
    Ok(ProgramAttestation {
        program_id,
        program_data_address,
        deployment_slot,
        code_hash: actual,
        observed_context_slot: program.context_slot.min(program_data.context_slot),
    })
}

impl From<QuorumError> for AttestationError {
    fn from(_: QuorumError) -> Self {
        Self::Quorum
    }
}
