//! Instruction processor.

use solana_escrow_wire::{
    AssetKind, EscrowInstructionV1, EscrowStateV1, EscrowStatus, InitializeParamsV1,
    NATIVE_VAULT_SEED, STATE_LEN, STATE_SEED, TOKEN_VAULT_SEED, VAULT_AUTHORITY_SEED,
};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
// Deprecated re-exports, kept deliberately: the split `solana-system-interface`
// and `solana-sdk-ids` crates would widen the dependency tree the auditor has
// to read, for identical bytes on chain.
#[allow(deprecated)]
use solana_program::{system_instruction, system_program};
use spl_token::state::{Account as TokenAccount, Mint};

use crate::{error::EscrowProgramError as Error, secret::verify_shared_secret};

/// Process one canonical instruction.
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo<'_>], data: &[u8]) -> ProgramResult {
    if program_id != &crate::id() {
        return Err(Error::InvalidAccounts.into());
    }
    let instruction = EscrowInstructionV1::decode(data)
        .map_err(|_| ProgramError::from(Error::InvalidInstruction))?;
    match instruction {
        EscrowInstructionV1::InitializeNative(params) => {
            initialize_native(program_id, accounts, params)
        }
        EscrowInstructionV1::InitializeSpl(params) => initialize_spl(program_id, accounts, params),
        EscrowInstructionV1::Fund => fund(program_id, accounts),
        EscrowInstructionV1::Claim { revealed_secret_be } => {
            claim(program_id, accounts, revealed_secret_be)
        }
        EscrowInstructionV1::Refund => refund(program_id, accounts),
        EscrowInstructionV1::Close => close(program_id, accounts),
    }
}

fn initialize_native(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    params: InitializeParamsV1,
) -> ProgramResult {
    let mut iterator = accounts.iter();
    let funder = next_account_info(&mut iterator)?;
    let state_account = next_account_info(&mut iterator)?;
    let vault_account = next_account_info(&mut iterator)?;
    let system = next_account_info(&mut iterator)?;
    ensure_no_extra(iterator)?;
    require_signer_writable(funder)?;
    require_writable(state_account)?;
    require_writable(vault_account)?;
    require_key(system, &system_program::id())?;
    require_uninitialized(state_account)?;
    require_uninitialized(vault_account)?;
    require_future_deadline(params.refund_after_unix)?;

    let (expected_state, state_bump) =
        Pubkey::find_program_address(&[STATE_SEED, &params.settlement_id], program_id);
    require_key(state_account, &expected_state)?;
    let (expected_vault, vault_bump) =
        Pubkey::find_program_address(&[NATIVE_VAULT_SEED, state_account.key.as_ref()], program_id);
    require_key(vault_account, &expected_vault)?;
    let (_, authority_bump) = Pubkey::find_program_address(
        &[VAULT_AUTHORITY_SEED, state_account.key.as_ref()],
        program_id,
    );

    create_pda_account(
        funder,
        state_account,
        system,
        Rent::get()
            .map_err(|_| Error::RentUnavailable)?
            .minimum_balance(STATE_LEN),
        STATE_LEN,
        program_id,
        &[STATE_SEED, &params.settlement_id, &[state_bump]],
    )?;
    create_pda_account(
        funder,
        vault_account,
        system,
        Rent::get()
            .map_err(|_| Error::RentUnavailable)?
            .minimum_balance(0),
        0,
        program_id,
        &[NATIVE_VAULT_SEED, state_account.key.as_ref(), &[vault_bump]],
    )?;

    let state = EscrowStateV1 {
        status: EscrowStatus::Initialized,
        asset_kind: AssetKind::NativeSol,
        state_bump,
        vault_bump,
        authority_bump,
        token_decimals: 0,
        settlement_id: params.settlement_id,
        terms_hash: params.terms_hash,
        setup_id: params.setup_id,
        funder: funder.key.to_bytes(),
        recipient: params.recipient,
        refund_recipient: params.refund_recipient,
        token_program: [0; 32],
        mint: [0; 32],
        vault: vault_account.key.to_bytes(),
        dom_adaptor_point: params.dom_adaptor_point,
        claim_point_ed25519: params.claim_point_ed25519,
        amount: params.amount,
        funded_amount: 0,
        refund_after_unix: params.refund_after_unix,
        terminal_slot: 0,
        revealed_secret_be: [0; 32],
    };
    save_state(state_account, &state)
}

fn initialize_spl(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    params: InitializeParamsV1,
) -> ProgramResult {
    let mut iterator = accounts.iter();
    let funder = next_account_info(&mut iterator)?;
    let state_account = next_account_info(&mut iterator)?;
    let authority = next_account_info(&mut iterator)?;
    let vault_account = next_account_info(&mut iterator)?;
    let mint_account = next_account_info(&mut iterator)?;
    let token_program = next_account_info(&mut iterator)?;
    let system = next_account_info(&mut iterator)?;
    ensure_no_extra(iterator)?;
    require_signer_writable(funder)?;
    require_writable(state_account)?;
    require_writable(vault_account)?;
    require_key(token_program, &spl_token::id())?;
    require_key(system, &system_program::id())?;
    require_owner(mint_account, token_program.key)?;
    require_uninitialized(state_account)?;
    require_uninitialized(vault_account)?;
    require_future_deadline(params.refund_after_unix)?;

    let mint =
        Mint::unpack(&mint_account.try_borrow_data()?).map_err(|_| Error::TokenAccountRejected)?;
    if !mint.is_initialized {
        return Err(Error::TokenAccountRejected.into());
    }

    let (expected_state, state_bump) =
        Pubkey::find_program_address(&[STATE_SEED, &params.settlement_id], program_id);
    require_key(state_account, &expected_state)?;
    let (expected_authority, authority_bump) = Pubkey::find_program_address(
        &[VAULT_AUTHORITY_SEED, state_account.key.as_ref()],
        program_id,
    );
    require_key(authority, &expected_authority)?;
    let (expected_vault, vault_bump) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, state_account.key.as_ref()], program_id);
    require_key(vault_account, &expected_vault)?;

    let rent = Rent::get().map_err(|_| Error::RentUnavailable)?;
    create_pda_account(
        funder,
        state_account,
        system,
        rent.minimum_balance(STATE_LEN),
        STATE_LEN,
        program_id,
        &[STATE_SEED, &params.settlement_id, &[state_bump]],
    )?;
    create_pda_account(
        funder,
        vault_account,
        system,
        rent.minimum_balance(TokenAccount::LEN),
        TokenAccount::LEN,
        token_program.key,
        &[TOKEN_VAULT_SEED, state_account.key.as_ref(), &[vault_bump]],
    )?;
    let initialize = spl_token::instruction::initialize_account3(
        token_program.key,
        vault_account.key,
        mint_account.key,
        authority.key,
    )?;
    invoke(
        &initialize,
        &[
            vault_account.clone(),
            mint_account.clone(),
            token_program.clone(),
        ],
    )?;

    let state = EscrowStateV1 {
        status: EscrowStatus::Initialized,
        asset_kind: AssetKind::LegacySpl,
        state_bump,
        vault_bump,
        authority_bump,
        token_decimals: mint.decimals,
        settlement_id: params.settlement_id,
        terms_hash: params.terms_hash,
        setup_id: params.setup_id,
        funder: funder.key.to_bytes(),
        recipient: params.recipient,
        refund_recipient: params.refund_recipient,
        token_program: token_program.key.to_bytes(),
        mint: mint_account.key.to_bytes(),
        vault: vault_account.key.to_bytes(),
        dom_adaptor_point: params.dom_adaptor_point,
        claim_point_ed25519: params.claim_point_ed25519,
        amount: params.amount,
        funded_amount: 0,
        refund_after_unix: params.refund_after_unix,
        terminal_slot: 0,
        revealed_secret_be: [0; 32],
    };
    save_state(state_account, &state)
}

fn fund(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let mut iterator = accounts.iter();
    let funder = next_account_info(&mut iterator)?;
    let state_account = next_account_info(&mut iterator)?;
    require_signer_writable(funder)?;
    require_writable(state_account)?;
    let mut state = load_state(program_id, state_account)?;
    require_state_pdas(program_id, state_account, &state)?;
    require_key(funder, &Pubkey::new_from_array(state.funder))?;
    if state.status != EscrowStatus::Initialized || state.funded_amount != 0 {
        return Err(Error::InvalidState.into());
    }

    match state.asset_kind {
        AssetKind::NativeSol => {
            let vault = next_account_info(&mut iterator)?;
            let system = next_account_info(&mut iterator)?;
            ensure_no_extra(iterator)?;
            require_writable(vault)?;
            require_key(system, &system_program::id())?;
            validate_native_vault(program_id, state_account, vault, &state)?;
            let rent_floor = Rent::get()
                .map_err(|_| Error::RentUnavailable)?
                .minimum_balance(0);
            if vault.lamports() != rent_floor {
                return Err(Error::InvalidAmount.into());
            }
            invoke(
                &system_instruction::transfer(funder.key, vault.key, state.amount),
                &[funder.clone(), vault.clone(), system.clone()],
            )?;
            if vault.lamports()
                != rent_floor
                    .checked_add(state.amount)
                    .ok_or(Error::Arithmetic)?
            {
                return Err(Error::InvalidAmount.into());
            }
        }
        AssetKind::LegacySpl => {
            let source = next_account_info(&mut iterator)?;
            let vault = next_account_info(&mut iterator)?;
            let mint = next_account_info(&mut iterator)?;
            let token_program = next_account_info(&mut iterator)?;
            ensure_no_extra(iterator)?;
            require_writable(source)?;
            require_writable(vault)?;
            validate_token_accounts(
                funder,
                state_account,
                source,
                vault,
                mint,
                token_program,
                &state,
            )?;
            let current = TokenAccount::unpack(&vault.try_borrow_data()?)
                .map_err(|_| Error::TokenAccountRejected)?;
            if current.amount != 0 {
                return Err(Error::InvalidAmount.into());
            }
            let transfer = spl_token::instruction::transfer_checked(
                token_program.key,
                source.key,
                mint.key,
                vault.key,
                funder.key,
                &[],
                state.amount,
                state.token_decimals,
            )?;
            invoke(
                &transfer,
                &[
                    source.clone(),
                    mint.clone(),
                    vault.clone(),
                    funder.clone(),
                    token_program.clone(),
                ],
            )?;
            let updated = TokenAccount::unpack(&vault.try_borrow_data()?)
                .map_err(|_| Error::TokenAccountRejected)?;
            if updated.amount != state.amount {
                return Err(Error::InvalidAmount.into());
            }
        }
    }
    state.funded_amount = state.amount;
    state.status = EscrowStatus::Funded;
    save_state(state_account, &state)
}

fn claim(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    revealed_secret_be: [u8; 32],
) -> ProgramResult {
    let mut iterator = accounts.iter();
    let state_account = next_account_info(&mut iterator)?;
    let mut state = load_state(program_id, state_account)?;
    require_state_pdas(program_id, state_account, &state)?;
    if state.status != EscrowStatus::Funded || state.funded_amount != state.amount {
        return Err(Error::InvalidState.into());
    }
    verify_shared_secret(revealed_secret_be, state.claim_point_ed25519)?;
    terminal_transfer(program_id, &mut iterator, state_account, &state, false)?;
    ensure_no_extra(iterator)?;
    state.status = EscrowStatus::Claimed;
    state.funded_amount = 0;
    state.revealed_secret_be = revealed_secret_be;
    state.terminal_slot = Clock::get().map_err(|_| Error::ClockUnavailable)?.slot;
    save_state(state_account, &state)
}

fn refund(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let mut iterator = accounts.iter();
    let state_account = next_account_info(&mut iterator)?;
    let mut state = load_state(program_id, state_account)?;
    require_state_pdas(program_id, state_account, &state)?;
    if state.status != EscrowStatus::Funded || state.funded_amount != state.amount {
        return Err(Error::InvalidState.into());
    }
    let clock = Clock::get().map_err(|_| Error::ClockUnavailable)?;
    if clock.unix_timestamp < state.refund_after_unix {
        return Err(Error::TimelockNotReached.into());
    }
    terminal_transfer(program_id, &mut iterator, state_account, &state, true)?;
    ensure_no_extra(iterator)?;
    state.status = EscrowStatus::Refunded;
    state.funded_amount = 0;
    state.revealed_secret_be = [0; 32];
    state.terminal_slot = clock.slot;
    save_state(state_account, &state)
}

fn terminal_transfer<'a, 'b>(
    program_id: &Pubkey,
    iterator: &mut core::slice::Iter<'a, AccountInfo<'b>>,
    state_account: &AccountInfo<'b>,
    state: &EscrowStateV1,
    refund: bool,
) -> ProgramResult {
    let destination_owner = Pubkey::new_from_array(if refund {
        state.refund_recipient
    } else {
        state.recipient
    });
    match state.asset_kind {
        AssetKind::NativeSol => {
            let vault = next_account_info(iterator)?;
            let destination = next_account_info(iterator)?;
            require_writable(vault)?;
            require_writable(destination)?;
            require_key(destination, &destination_owner)?;
            validate_native_vault(program_id, state_account, vault, state)?;
            move_lamports(vault, destination, state.amount)?;
            let rent_floor = Rent::get()
                .map_err(|_| Error::RentUnavailable)?
                .minimum_balance(0);
            if vault.lamports() != rent_floor {
                return Err(Error::InvalidAmount.into());
            }
        }
        AssetKind::LegacySpl => {
            let authority = next_account_info(iterator)?;
            let vault = next_account_info(iterator)?;
            let destination = next_account_info(iterator)?;
            let mint = next_account_info(iterator)?;
            let token_program = next_account_info(iterator)?;
            require_writable(vault)?;
            require_writable(destination)?;
            require_key(token_program, &spl_token::id())?;
            require_key(mint, &Pubkey::new_from_array(state.mint))?;
            validate_vault_authority(program_id, state_account, authority, state)?;
            validate_vault_token(vault, authority, mint, token_program, state)?;
            let destination_state = TokenAccount::unpack(&destination.try_borrow_data()?)
                .map_err(|_| Error::TokenAccountRejected)?;
            if destination.owner != token_program.key
                || destination_state.mint != *mint.key
                || destination_state.owner != destination_owner
            {
                return Err(Error::TokenAccountRejected.into());
            }
            let transfer = spl_token::instruction::transfer_checked(
                token_program.key,
                vault.key,
                mint.key,
                destination.key,
                authority.key,
                &[],
                state.amount,
                state.token_decimals,
            )?;
            let bump = [state.authority_bump];
            let authority_seeds: &[&[u8]] =
                &[VAULT_AUTHORITY_SEED, state_account.key.as_ref(), &bump];
            invoke_signed(
                &transfer,
                &[
                    vault.clone(),
                    mint.clone(),
                    destination.clone(),
                    authority.clone(),
                    token_program.clone(),
                ],
                &[authority_seeds],
            )?;
            let updated = TokenAccount::unpack(&vault.try_borrow_data()?)
                .map_err(|_| Error::TokenAccountRejected)?;
            if updated.amount != 0 {
                return Err(Error::InvalidAmount.into());
            }
        }
    }
    Ok(())
}

fn close(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let mut iterator = accounts.iter();
    let state_account = next_account_info(&mut iterator)?;
    let state = load_state(program_id, state_account)?;
    require_state_pdas(program_id, state_account, &state)?;
    if !matches!(state.status, EscrowStatus::Claimed | EscrowStatus::Refunded) {
        return Err(Error::InvalidState.into());
    }
    match state.asset_kind {
        AssetKind::NativeSol => {
            let vault = next_account_info(&mut iterator)?;
            let funder = next_account_info(&mut iterator)?;
            ensure_no_extra(iterator)?;
            require_writable(vault)?;
            require_writable(funder)?;
            require_key(funder, &Pubkey::new_from_array(state.funder))?;
            validate_native_vault(program_id, state_account, vault, &state)?;
            drain_account(vault, funder)?;
            drain_account(state_account, funder)
        }
        AssetKind::LegacySpl => {
            let authority = next_account_info(&mut iterator)?;
            let vault = next_account_info(&mut iterator)?;
            let funder = next_account_info(&mut iterator)?;
            let token_program = next_account_info(&mut iterator)?;
            ensure_no_extra(iterator)?;
            require_writable(vault)?;
            require_writable(funder)?;
            require_key(funder, &Pubkey::new_from_array(state.funder))?;
            require_key(token_program, &spl_token::id())?;
            validate_vault_authority(program_id, state_account, authority, &state)?;
            let vault_state = TokenAccount::unpack(&vault.try_borrow_data()?)
                .map_err(|_| Error::TokenAccountRejected)?;
            if vault.owner != token_program.key
                || vault_state.owner != *authority.key
                || vault_state.amount != 0
            {
                return Err(Error::TokenAccountRejected.into());
            }
            let close_instruction = spl_token::instruction::close_account(
                token_program.key,
                vault.key,
                funder.key,
                authority.key,
                &[],
            )?;
            let bump = [state.authority_bump];
            let authority_seeds: &[&[u8]] =
                &[VAULT_AUTHORITY_SEED, state_account.key.as_ref(), &bump];
            invoke_signed(
                &close_instruction,
                &[
                    vault.clone(),
                    funder.clone(),
                    authority.clone(),
                    token_program.clone(),
                ],
                &[authority_seeds],
            )?;
            drain_account(state_account, funder)
        }
    }
}

fn create_pda_account<'a>(
    payer: &AccountInfo<'a>,
    account: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    lamports: u64,
    space: usize,
    owner: &Pubkey,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let space = u64::try_from(space).map_err(|_| Error::Arithmetic)?;
    let instruction =
        system_instruction::create_account(payer.key, account.key, lamports, space, owner);
    invoke_signed(
        &instruction,
        &[payer.clone(), account.clone(), system.clone()],
        &[signer_seeds],
    )
}

fn validate_token_accounts(
    funder: &AccountInfo<'_>,
    state_account: &AccountInfo<'_>,
    source: &AccountInfo<'_>,
    vault: &AccountInfo<'_>,
    mint: &AccountInfo<'_>,
    token_program: &AccountInfo<'_>,
    state: &EscrowStateV1,
) -> ProgramResult {
    require_key(token_program, &spl_token::id())?;
    require_key(mint, &Pubkey::new_from_array(state.mint))?;
    let (authority, _) = Pubkey::find_program_address(
        &[VAULT_AUTHORITY_SEED, state_account.key.as_ref()],
        &crate::id(),
    );
    validate_vault_token_key(&crate::id(), state_account, vault, state)?;
    if source.owner != token_program.key || vault.owner != token_program.key {
        return Err(Error::TokenAccountRejected.into());
    }
    let source_state = TokenAccount::unpack(&source.try_borrow_data()?)
        .map_err(|_| Error::TokenAccountRejected)?;
    if source_state.owner != *funder.key
        || source_state.mint != *mint.key
        || source_state.amount < state.amount
    {
        return Err(Error::TokenAccountRejected.into());
    }
    let vault_state =
        TokenAccount::unpack(&vault.try_borrow_data()?).map_err(|_| Error::TokenAccountRejected)?;
    if vault_state.owner != authority || vault_state.mint != *mint.key {
        return Err(Error::TokenAccountRejected.into());
    }
    Ok(())
}

fn validate_native_vault(
    program_id: &Pubkey,
    state_account: &AccountInfo<'_>,
    vault: &AccountInfo<'_>,
    state: &EscrowStateV1,
) -> ProgramResult {
    let (expected, bump) =
        Pubkey::find_program_address(&[NATIVE_VAULT_SEED, state_account.key.as_ref()], program_id);
    if vault.key != &expected
        || state.vault_bump != bump
        || vault.key.to_bytes() != state.vault
        || vault.owner != program_id
        || !vault.data_is_empty()
    {
        return Err(Error::InvalidPda.into());
    }
    Ok(())
}

fn validate_vault_token_key(
    program_id: &Pubkey,
    state_account: &AccountInfo<'_>,
    vault: &AccountInfo<'_>,
    state: &EscrowStateV1,
) -> ProgramResult {
    let (expected, bump) =
        Pubkey::find_program_address(&[TOKEN_VAULT_SEED, state_account.key.as_ref()], program_id);
    if vault.key != &expected || state.vault_bump != bump || vault.key.to_bytes() != state.vault {
        return Err(Error::InvalidPda.into());
    }
    Ok(())
}

fn validate_vault_authority(
    program_id: &Pubkey,
    state_account: &AccountInfo<'_>,
    authority: &AccountInfo<'_>,
    state: &EscrowStateV1,
) -> ProgramResult {
    let (expected, bump) = Pubkey::find_program_address(
        &[VAULT_AUTHORITY_SEED, state_account.key.as_ref()],
        program_id,
    );
    if authority.key != &expected || state.authority_bump != bump {
        return Err(Error::InvalidPda.into());
    }
    Ok(())
}

fn validate_vault_token(
    vault: &AccountInfo<'_>,
    authority: &AccountInfo<'_>,
    mint: &AccountInfo<'_>,
    token_program: &AccountInfo<'_>,
    state: &EscrowStateV1,
) -> ProgramResult {
    if vault.key.to_bytes() != state.vault || vault.owner != token_program.key {
        return Err(Error::TokenAccountRejected.into());
    }
    let token =
        TokenAccount::unpack(&vault.try_borrow_data()?).map_err(|_| Error::TokenAccountRejected)?;
    if token.owner != *authority.key || token.mint != *mint.key || token.amount != state.amount {
        return Err(Error::TokenAccountRejected.into());
    }
    Ok(())
}

fn require_state_pdas(
    program_id: &Pubkey,
    state_account: &AccountInfo<'_>,
    state: &EscrowStateV1,
) -> ProgramResult {
    let (expected, bump) =
        Pubkey::find_program_address(&[STATE_SEED, &state.settlement_id], program_id);
    if state_account.key != &expected || state.state_bump != bump {
        return Err(Error::InvalidPda.into());
    }
    Ok(())
}

fn load_state(
    program_id: &Pubkey,
    account: &AccountInfo<'_>,
) -> Result<EscrowStateV1, ProgramError> {
    require_writable(account)?;
    require_owner(account, program_id)?;
    EscrowStateV1::decode(&account.try_borrow_data()?).map_err(|_| Error::InvalidState.into())
}

fn save_state(account: &AccountInfo<'_>, state: &EscrowStateV1) -> ProgramResult {
    state.validate().map_err(|_| Error::InvalidState)?;
    let encoded = state.encode();
    let mut data = account
        .try_borrow_mut_data()
        .map_err(|_| Error::AccountBorrow)?;
    if data.len() != STATE_LEN {
        return Err(Error::InvalidState.into());
    }
    data.copy_from_slice(&encoded);
    Ok(())
}

fn move_lamports(
    source: &AccountInfo<'_>,
    destination: &AccountInfo<'_>,
    amount: u64,
) -> ProgramResult {
    let source_value = source.lamports();
    let destination_value = destination.lamports();
    let new_source = source_value.checked_sub(amount).ok_or(Error::Arithmetic)?;
    let new_destination = destination_value
        .checked_add(amount)
        .ok_or(Error::Arithmetic)?;
    **source
        .try_borrow_mut_lamports()
        .map_err(|_| Error::AccountBorrow)? = new_source;
    **destination
        .try_borrow_mut_lamports()
        .map_err(|_| Error::AccountBorrow)? = new_destination;
    Ok(())
}

fn drain_account(source: &AccountInfo<'_>, destination: &AccountInfo<'_>) -> ProgramResult {
    let source_value = source.lamports();
    let destination_value = destination.lamports();
    let new_destination = destination_value
        .checked_add(source_value)
        .ok_or(Error::Arithmetic)?;
    **source
        .try_borrow_mut_lamports()
        .map_err(|_| Error::AccountBorrow)? = 0;
    **destination
        .try_borrow_mut_lamports()
        .map_err(|_| Error::AccountBorrow)? = new_destination;
    Ok(())
}

fn require_uninitialized(account: &AccountInfo<'_>) -> ProgramResult {
    if account.lamports() != 0 || !account.data_is_empty() || account.executable {
        return Err(Error::AlreadyInitialized.into());
    }
    Ok(())
}

fn require_signer_writable(account: &AccountInfo<'_>) -> ProgramResult {
    if !account.is_signer {
        return Err(Error::MissingSignature.into());
    }
    require_writable(account)
}

fn require_writable(account: &AccountInfo<'_>) -> ProgramResult {
    if !account.is_writable {
        return Err(Error::InvalidAccounts.into());
    }
    Ok(())
}

fn require_owner(account: &AccountInfo<'_>, owner: &Pubkey) -> ProgramResult {
    if account.owner != owner {
        return Err(Error::InvalidOwner.into());
    }
    Ok(())
}

fn require_key(account: &AccountInfo<'_>, key: &Pubkey) -> ProgramResult {
    if account.key != key {
        return Err(Error::InvalidAccounts.into());
    }
    Ok(())
}

fn require_future_deadline(deadline: i64) -> ProgramResult {
    let now = Clock::get()
        .map_err(|_| Error::ClockUnavailable)?
        .unix_timestamp;
    if deadline <= now {
        return Err(Error::InvalidState.into());
    }
    Ok(())
}

fn ensure_no_extra<'a, 'b>(mut iterator: core::slice::Iter<'a, AccountInfo<'b>>) -> ProgramResult {
    if iterator.next().is_some() {
        return Err(Error::InvalidAccounts.into());
    }
    Ok(())
}
