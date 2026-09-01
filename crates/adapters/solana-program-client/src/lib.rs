//! Exact account metas and instruction data for the DOM Solana escrow.

#![forbid(unsafe_code)]

use solana_escrow_wire::{EscrowInstructionV1, InitializeParamsV1};
use solana_profile::{SolanaAssetV1, ValidatedSolanaSetup};
use solana_types::{
    SolanaAccountMeta as Meta, SolanaInstruction, SolanaPubkey, LEGACY_TOKEN_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    #[error("account is required for selected asset")]
    MissingAccount,
    #[error("unexpected account for selected asset")]
    UnexpectedAccount,
}

fn ro(pubkey: SolanaPubkey) -> Meta {
    Meta {
        pubkey,
        is_signer: false,
        is_writable: false,
    }
}
fn rw(pubkey: SolanaPubkey) -> Meta {
    Meta {
        pubkey,
        is_signer: false,
        is_writable: true,
    }
}
fn signer_rw(pubkey: SolanaPubkey) -> Meta {
    Meta {
        pubkey,
        is_signer: true,
        is_writable: true,
    }
}

fn initialize_data(setup: &ValidatedSolanaSetup) -> InitializeParamsV1 {
    InitializeParamsV1 {
        settlement_id: setup.settlement_id(),
        terms_hash: setup.terms_hash(),
        setup_id: setup.setup_id(),
        recipient: setup.recipient().0,
        refund_recipient: setup.refund_recipient().0,
        dom_adaptor_point: setup.claim().secp_compressed,
        claim_point_ed25519: setup.claim().ed_compressed,
        amount: setup.amount(),
        refund_after_unix: setup.refund_after_unix(),
    }
}

pub fn initialize(setup: &ValidatedSolanaSetup) -> SolanaInstruction {
    let (data, accounts) = match setup.asset() {
        SolanaAssetV1::NativeSol => (
            EscrowInstructionV1::InitializeNative(initialize_data(setup)).encode(),
            vec![
                signer_rw(setup.funder()),
                rw(setup.state_pda()),
                rw(setup.vault_pda()),
                ro(SYSTEM_PROGRAM_ID),
            ],
        ),
        SolanaAssetV1::LegacySpl { mint, .. } => (
            EscrowInstructionV1::InitializeSpl(initialize_data(setup)).encode(),
            vec![
                signer_rw(setup.funder()),
                rw(setup.state_pda()),
                ro(setup.vault_authority()),
                rw(setup.vault_pda()),
                ro(mint),
                ro(LEGACY_TOKEN_PROGRAM_ID),
                ro(SYSTEM_PROGRAM_ID),
            ],
        ),
    };
    SolanaInstruction {
        program_id: setup.program_id(),
        accounts,
        data,
    }
}

pub fn fund(
    setup: &ValidatedSolanaSetup,
    source_token_account: Option<SolanaPubkey>,
) -> Result<SolanaInstruction, ClientError> {
    let accounts = match setup.asset() {
        SolanaAssetV1::NativeSol => {
            if source_token_account.is_some() {
                return Err(ClientError::UnexpectedAccount);
            }
            vec![
                signer_rw(setup.funder()),
                rw(setup.state_pda()),
                rw(setup.vault_pda()),
                ro(SYSTEM_PROGRAM_ID),
            ]
        }
        SolanaAssetV1::LegacySpl { mint, .. } => {
            let source = source_token_account.ok_or(ClientError::MissingAccount)?;
            vec![
                signer_rw(setup.funder()),
                rw(setup.state_pda()),
                rw(source),
                rw(setup.vault_pda()),
                ro(mint),
                ro(LEGACY_TOKEN_PROGRAM_ID),
            ]
        }
    };
    Ok(SolanaInstruction {
        program_id: setup.program_id(),
        accounts,
        data: EscrowInstructionV1::Fund.encode(),
    })
}

pub fn claim(
    setup: &ValidatedSolanaSetup,
    revealed_secret_be: [u8; 32],
    recipient_token_account: Option<SolanaPubkey>,
) -> Result<SolanaInstruction, ClientError> {
    terminal_transfer(setup, revealed_secret_be, recipient_token_account, false)
}

pub fn refund(
    setup: &ValidatedSolanaSetup,
    refund_token_account: Option<SolanaPubkey>,
) -> Result<SolanaInstruction, ClientError> {
    terminal_transfer(setup, [0; 32], refund_token_account, true)
}

fn terminal_transfer(
    setup: &ValidatedSolanaSetup,
    secret: [u8; 32],
    destination_token_account: Option<SolanaPubkey>,
    refund: bool,
) -> Result<SolanaInstruction, ClientError> {
    let recipient = if refund {
        setup.refund_recipient()
    } else {
        setup.recipient()
    };
    let accounts = match setup.asset() {
        SolanaAssetV1::NativeSol => {
            if destination_token_account.is_some() {
                return Err(ClientError::UnexpectedAccount);
            }
            vec![rw(setup.state_pda()), rw(setup.vault_pda()), rw(recipient)]
        }
        SolanaAssetV1::LegacySpl { mint, .. } => {
            let destination = destination_token_account.ok_or(ClientError::MissingAccount)?;
            vec![
                rw(setup.state_pda()),
                ro(setup.vault_authority()),
                rw(setup.vault_pda()),
                rw(destination),
                ro(mint),
                ro(LEGACY_TOKEN_PROGRAM_ID),
            ]
        }
    };
    let data = if refund {
        EscrowInstructionV1::Refund.encode()
    } else {
        EscrowInstructionV1::Claim {
            revealed_secret_be: secret,
        }
        .encode()
    };
    Ok(SolanaInstruction {
        program_id: setup.program_id(),
        accounts,
        data,
    })
}

pub fn close(setup: &ValidatedSolanaSetup) -> SolanaInstruction {
    let accounts = match setup.asset() {
        SolanaAssetV1::NativeSol => vec![
            rw(setup.state_pda()),
            rw(setup.vault_pda()),
            rw(setup.funder()),
        ],
        SolanaAssetV1::LegacySpl { .. } => vec![
            rw(setup.state_pda()),
            ro(setup.vault_authority()),
            rw(setup.vault_pda()),
            rw(setup.funder()),
            ro(LEGACY_TOKEN_PROGRAM_ID),
        ],
    };
    SolanaInstruction {
        program_id: setup.program_id(),
        accounts,
        data: EscrowInstructionV1::Close.encode(),
    }
}
