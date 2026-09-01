//! Host-side execution of the program's native-SOL paths.
//!
//! The processor is run as-is through `solana_program::program_stubs`: the
//! clock and rent sysvars come from a thread-local test clock, and CPI is
//! emulated only for the one system-program instruction the native paths
//! issue (Transfer). Nothing in the processor is mocked or bypassed — every
//! PDA check, state transition, secret verification and lamport movement is
//! the deployed code path. Account creation (initialize's CPI) is exercised
//! up to its refusals; creating accounts is the system program's job and is
//! covered on a live validator, not here.

use std::cell::Cell;
use std::sync::Once;

use dom_solana_escrow::processor::process as process_instruction;
use solana_escrow_wire::{
    AssetKind, EscrowInstructionV1, EscrowStateV1, EscrowStatus, InitializeParamsV1,
    NATIVE_VAULT_SEED, STATE_LEN, STATE_SEED, VAULT_AUTHORITY_SEED,
};
use solana_program::program_stubs::{set_syscall_stubs, SyscallStubs};
#[allow(deprecated)]
use solana_program::system_program;
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint::ProgramResult, instruction::Instruction,
    program_error::ProgramError, pubkey::Pubkey, rent::Rent,
};

thread_local! {
    static NOW_UNIX: Cell<i64> = const { Cell::new(1_900_000_000) };
}

struct TestStubs;

impl SyscallStubs for TestStubs {
    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        let clock = Clock {
            slot: 42,
            epoch_start_timestamp: 0,
            epoch: 1,
            leader_schedule_epoch: 1,
            unix_timestamp: NOW_UNIX.with(Cell::get),
        };
        unsafe {
            *(var_addr as *mut Clock) = clock;
        }
        0
    }

    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        unsafe {
            *(var_addr as *mut Rent) = Rent::default();
        }
        0
    }

    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        account_infos: &[AccountInfo],
        _signers_seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        // The native paths CPI exactly one instruction: SystemInstruction::
        // Transfer (bincode discriminant 2). Everything else is refused so a
        // processor change that starts invoking something new fails loudly.
        if instruction.program_id != system_program::id()
            || instruction.data.len() != 12
            || instruction.data[0..4] != [2, 0, 0, 0]
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let lamports = u64::from_le_bytes(instruction.data[4..12].try_into().unwrap());
        let from_key = instruction.accounts[0].pubkey;
        let to_key = instruction.accounts[1].pubkey;
        let from = account_infos
            .iter()
            .find(|info| *info.key == from_key)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let to = account_infos
            .iter()
            .find(|info| *info.key == to_key)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !from.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
        let from_balance = from.lamports();
        let to_balance = to.lamports();
        let new_from = from_balance
            .checked_sub(lamports)
            .ok_or(ProgramError::InsufficientFunds)?;
        **from.try_borrow_mut_lamports()? = new_from;
        **to.try_borrow_mut_lamports()? = to_balance + lamports;
        Ok(())
    }
}

fn install_stubs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        set_syscall_stubs(Box::new(TestStubs));
    });
}

fn set_now(unix: i64) {
    NOW_UNIX.with(|cell| cell.set(unix));
}

// A witness in the 252-bit domain and its ed25519 claim point.
fn witness() -> ([u8; 32], [u8; 32]) {
    let mut little_endian = [0u8; 32];
    little_endian[0] = 7;
    little_endian[7] = 9;
    let scalar = curve25519_dalek::scalar::Scalar::from_canonical_bytes(little_endian).unwrap();
    let point = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &scalar;
    let mut big_endian = little_endian;
    big_endian.reverse();
    (big_endian, point.compress().to_bytes())
}

struct Acct {
    key: Pubkey,
    lamports: u64,
    data: Vec<u8>,
    owner: Pubkey,
    signer: bool,
    writable: bool,
}

impl Acct {
    fn plain(key: Pubkey, lamports: u64) -> Self {
        Self {
            key,
            lamports,
            data: Vec::new(),
            owner: system_program::id(),
            signer: false,
            writable: true,
        }
    }
}

fn infos(accts: &mut [Acct]) -> Vec<AccountInfo<'_>> {
    accts
        .iter_mut()
        .map(|acct| {
            AccountInfo::new(
                &acct.key,
                acct.signer,
                acct.writable,
                &mut acct.lamports,
                &mut acct.data,
                &acct.owner,
                false,
                0,
            )
        })
        .collect()
}

const SETTLEMENT: [u8; 32] = [0x11; 32];
const AMOUNT: u64 = 5_000_000;

struct Escrow {
    program: Pubkey,
    state_key: Pubkey,
    vault_key: Pubkey,
    funder_key: Pubkey,
    recipient_key: Pubkey,
    refund_key: Pubkey,
    claim_point: [u8; 32],
    secret_be: [u8; 32],
    rent_floor: u64,
    state: EscrowStateV1,
}

fn escrow() -> Escrow {
    install_stubs();
    set_now(1_900_000_000);
    let program = dom_solana_escrow::id();
    let (secret_be, claim_point) = witness();
    let funder_key = Pubkey::new_from_array([0xF1; 32]);
    let recipient_key = Pubkey::new_from_array([0xC1; 32]);
    let refund_key = Pubkey::new_from_array([0xB1; 32]);
    let (state_key, state_bump) =
        Pubkey::find_program_address(&[STATE_SEED, &SETTLEMENT], &program);
    let (vault_key, vault_bump) =
        Pubkey::find_program_address(&[NATIVE_VAULT_SEED, state_key.as_ref()], &program);
    let (_, authority_bump) =
        Pubkey::find_program_address(&[VAULT_AUTHORITY_SEED, state_key.as_ref()], &program);
    let state = EscrowStateV1 {
        status: EscrowStatus::Funded,
        asset_kind: AssetKind::NativeSol,
        state_bump,
        vault_bump,
        authority_bump,
        token_decimals: 0,
        settlement_id: SETTLEMENT,
        terms_hash: [0x22; 32],
        setup_id: [0x33; 32],
        funder: funder_key.to_bytes(),
        recipient: recipient_key.to_bytes(),
        refund_recipient: refund_key.to_bytes(),
        token_program: [0; 32],
        mint: [0; 32],
        vault: vault_key.to_bytes(),
        dom_adaptor_point: {
            let mut point = [0x44; 33];
            point[0] = 0x02;
            point
        },
        claim_point_ed25519: claim_point,
        amount: AMOUNT,
        funded_amount: AMOUNT,
        refund_after_unix: 2_000_000_000,
        terminal_slot: 0,
        revealed_secret_be: [0; 32],
    };
    Escrow {
        program,
        state_key,
        vault_key,
        funder_key,
        recipient_key,
        refund_key,
        claim_point,
        secret_be,
        rent_floor: Rent::default().minimum_balance(0),
        state,
    }
}

impl Escrow {
    fn state_acct(&self) -> Acct {
        Acct {
            key: self.state_key,
            lamports: Rent::default().minimum_balance(STATE_LEN),
            data: self.state.encode().to_vec(),
            owner: self.program,
            signer: false,
            writable: true,
        }
    }

    fn vault_acct(&self, funded: bool) -> Acct {
        Acct {
            key: self.vault_key,
            lamports: self.rent_floor + if funded { AMOUNT } else { 0 },
            data: Vec::new(),
            owner: self.program,
            signer: false,
            writable: true,
        }
    }

    fn decode_state(&self, accts: &[Acct]) -> EscrowStateV1 {
        EscrowStateV1::decode(&accts[0].data).expect("state decodes")
    }
}

fn claim_data(secret_be: [u8; 32]) -> Vec<u8> {
    EscrowInstructionV1::Claim {
        revealed_secret_be: secret_be,
    }
    .encode()
}

#[test]
fn claim_verifies_the_witness_moves_the_amount_and_records_the_reveal() {
    let escrow = escrow();
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        Acct::plain(escrow.recipient_key, 1),
    ];
    let infos = infos(&mut accts);
    process_instruction(&escrow.program, &infos, &claim_data(escrow.secret_be))
        .expect("claim succeeds");
    drop(infos);
    let state = escrow.decode_state(&accts);
    assert_eq!(state.status, EscrowStatus::Claimed);
    assert_eq!(state.funded_amount, 0);
    assert_eq!(state.revealed_secret_be, escrow.secret_be);
    assert_eq!(state.terminal_slot, 42);
    assert_eq!(accts[1].lamports, escrow.rent_floor, "vault back to floor");
    assert_eq!(accts[2].lamports, 1 + AMOUNT, "recipient credited exactly");
}

#[test]
fn claim_refuses_a_wrong_secret_and_an_out_of_domain_secret() {
    let escrow = escrow();
    // Wrong witness: correct domain, wrong discrete log.
    let mut wrong = escrow.secret_be;
    wrong[31] ^= 1;
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        Acct::plain(escrow.recipient_key, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(wrong)).is_err());
    drop(infos_v);

    // Out of the 252-bit domain: high nibble of the top little-endian byte.
    // A syscall reducing modulo the order might accept it; the program must
    // refuse before asking.
    let mut out_of_domain = escrow.secret_be;
    out_of_domain[0] |= 0xf0;
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(out_of_domain)).is_err());
    drop(infos_v);
    assert_eq!(
        escrow.decode_state(&accts).status,
        EscrowStatus::Funded,
        "no refused claim moved the state"
    );
    assert_eq!(accts[1].lamports, escrow.rent_floor + AMOUNT);
}

#[test]
fn claim_refuses_a_substituted_recipient_or_vault_or_state() {
    let escrow = escrow();
    let attacker = Pubkey::new_from_array([0xEE; 32]);

    // Substituted destination.
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        Acct::plain(attacker, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(escrow.secret_be)).is_err());
    drop(infos_v);

    // Substituted vault: right recipient, wrong vault account.
    let mut vault = escrow.vault_acct(true);
    vault.key = attacker;
    let mut accts = vec![
        escrow.state_acct(),
        vault,
        Acct::plain(escrow.recipient_key, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(escrow.secret_be)).is_err());
    drop(infos_v);

    // Substituted state account: correct layout under a foreign key.
    let mut state = escrow.state_acct();
    state.key = attacker;
    let mut accts = vec![
        state,
        escrow.vault_acct(true),
        Acct::plain(escrow.recipient_key, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(escrow.secret_be)).is_err());
}

#[test]
fn claim_refuses_a_trailing_extra_account() {
    let escrow = escrow();
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        Acct::plain(escrow.recipient_key, 1),
        Acct::plain(Pubkey::new_from_array([0xEE; 32]), 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(escrow.secret_be)).is_err());
}

#[test]
fn refund_waits_for_the_timelock_and_then_pays_the_refund_recipient() {
    let escrow = escrow();
    let refund_data = EscrowInstructionV1::Refund.encode();

    // One second before the deadline: refused.
    set_now(1_999_999_999);
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        Acct::plain(escrow.refund_key, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &refund_data).is_err());
    drop(infos_v);
    assert_eq!(escrow.decode_state(&accts).status, EscrowStatus::Funded);

    // At the deadline: paid, and the reveal field stays zero.
    set_now(2_000_000_000);
    let infos_v = infos(&mut accts);
    process_instruction(&escrow.program, &infos_v, &refund_data).expect("refund succeeds");
    drop(infos_v);
    let state = escrow.decode_state(&accts);
    assert_eq!(state.status, EscrowStatus::Refunded);
    assert_eq!(state.revealed_secret_be, [0; 32]);
    assert_eq!(accts[2].lamports, 1 + AMOUNT);

    // A claim after the refund is a double terminal: refused.
    set_now(2_000_000_001);
    accts[2] = Acct::plain(escrow.recipient_key, 1);
    accts[1].lamports = escrow.rent_floor + AMOUNT;
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &claim_data(escrow.secret_be)).is_err());
}

#[test]
fn refund_refuses_a_substituted_refund_destination() {
    let escrow = escrow();
    set_now(2_000_000_001);
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        // The claim recipient is not the refund recipient.
        Acct::plain(escrow.recipient_key, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(
        &escrow.program,
        &infos_v,
        &EscrowInstructionV1::Refund.encode()
    )
    .is_err());
}

#[test]
fn fund_moves_exactly_the_amount_once() {
    let mut escrow = escrow();
    escrow.state.status = EscrowStatus::Initialized;
    escrow.state.funded_amount = 0;
    let fund_data = EscrowInstructionV1::Fund.encode();
    let mut accts = vec![
        Acct {
            signer: true,
            ..Acct::plain(escrow.funder_key, escrow.rent_floor + 2 * AMOUNT)
        },
        escrow.state_acct(),
        escrow.vault_acct(false),
        Acct {
            writable: false,
            ..Acct::plain(system_program::id(), 1)
        },
    ];
    let infos_v = infos(&mut accts);
    process_instruction(&escrow.program, &infos_v, &fund_data).expect("fund succeeds");
    drop(infos_v);
    let state = EscrowStateV1::decode(&accts[1].data).expect("state");
    assert_eq!(state.status, EscrowStatus::Funded);
    assert_eq!(state.funded_amount, AMOUNT);
    assert_eq!(accts[2].lamports, escrow.rent_floor + AMOUNT);

    // Funding twice is refused by state, and by the vault balance check.
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &fund_data).is_err());
    drop(infos_v);

    // A non-funder cannot fund.
    let mut escrow2 = escrow;
    escrow2.state.status = EscrowStatus::Initialized;
    escrow2.state.funded_amount = 0;
    let mut accts = vec![
        Acct {
            signer: true,
            ..Acct::plain(
                Pubkey::new_from_array([0xEE; 32]),
                escrow2.rent_floor + 2 * AMOUNT,
            )
        },
        escrow2.state_acct(),
        escrow2.vault_acct(false),
        Acct {
            writable: false,
            ..Acct::plain(system_program::id(), 1)
        },
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow2.program, &infos_v, &fund_data).is_err());
}

#[test]
fn close_runs_only_after_a_terminal_state_and_drains_to_the_funder() {
    let escrow = escrow();
    let close_data = EscrowInstructionV1::Close.encode();

    // Funded is not terminal: refused.
    let mut accts = vec![
        escrow.state_acct(),
        escrow.vault_acct(true),
        Acct::plain(escrow.funder_key, 1),
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &close_data).is_err());
    drop(infos_v);

    // After a claim, close returns the vault floor and the state rent.
    let mut claimed = escrow.state;
    claimed.status = EscrowStatus::Claimed;
    claimed.funded_amount = 0;
    claimed.revealed_secret_be = escrow.secret_be;
    claimed.terminal_slot = 42;
    let state_rent = Rent::default().minimum_balance(STATE_LEN);
    let mut accts = vec![
        Acct {
            data: claimed.encode().to_vec(),
            ..escrow.state_acct()
        },
        escrow.vault_acct(false),
        Acct::plain(escrow.funder_key, 1),
    ];
    let infos_v = infos(&mut accts);
    process_instruction(&escrow.program, &infos_v, &close_data).expect("close succeeds");
    drop(infos_v);
    assert_eq!(accts[0].lamports, 0, "state drained");
    assert_eq!(accts[1].lamports, 0, "vault drained");
    assert_eq!(accts[2].lamports, 1 + escrow.rent_floor + state_rent);
}

#[test]
fn initialize_refuses_a_past_deadline_and_substituted_pdas() {
    let escrow = escrow();
    let params = InitializeParamsV1 {
        settlement_id: SETTLEMENT,
        terms_hash: [0x22; 32],
        setup_id: [0x33; 32],
        recipient: escrow.recipient_key.to_bytes(),
        refund_recipient: escrow.refund_key.to_bytes(),
        dom_adaptor_point: {
            let mut point = [0x44; 33];
            point[0] = 0x02;
            point
        },
        claim_point_ed25519: escrow.claim_point,
        amount: AMOUNT,
        refund_after_unix: 1_800_000_000, // in the past for the test clock
    };
    let data = EscrowInstructionV1::InitializeNative(params).encode();
    let mut accts = vec![
        Acct {
            signer: true,
            ..Acct::plain(escrow.funder_key, 10 * AMOUNT)
        },
        Acct::plain(escrow.state_key, 0),
        Acct::plain(escrow.vault_key, 0),
        Acct {
            writable: false,
            ..Acct::plain(system_program::id(), 1)
        },
    ];
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &data).is_err());
    drop(infos_v);

    // Future deadline but a substituted state PDA: refused before any CPI.
    let mut future = params;
    future.refund_after_unix = 2_000_000_000;
    let data = EscrowInstructionV1::InitializeNative(future).encode();
    accts[1].key = Pubkey::new_from_array([0xEE; 32]);
    let infos_v = infos(&mut accts);
    assert!(process_instruction(&escrow.program, &infos_v, &data).is_err());
}
