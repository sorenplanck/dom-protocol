//! Finalized Solana escrow observer and field-by-field evidence verifier.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use solana_escrow_wire::{AssetKind, EscrowInstructionV1, EscrowStateV1, EscrowStatus, STATE_LEN};
use solana_evidence::{
    SolanaClaimEvidenceV1, SolanaEvidenceBodyV1, SolanaEvidenceEnvelopeV1, SolanaFundingEvidenceV1,
    SolanaRefundEvidenceV1, EVIDENCE_VERSION,
};
use solana_profile::{SolanaAdapterProfileV1, SolanaAssetV1, ValidatedSolanaSetup};
use solana_program_attestation::{attest_immutable_program, ProgramAttestation};
use solana_rpc::SolanaRpc;
use solana_rpc_pool::{QuorumError, SolanaRpcPool};
use solana_types::{
    Commitment, LegacyTokenAccount, SolanaAccountSnapshot, SolanaPubkey, SolanaSignature,
};
use xmr_dleq_sigma::revealed_dom_secret_to_xmr_scalar;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationKind {
    Funding,
    Claim,
    Refund,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObserverError {
    #[error("RPC quorum unavailable or divergent")]
    Quorum,
    #[error("signature is not successful and finalized")]
    NotFinalized,
    #[error("transaction or program instruction is invalid")]
    InvalidTransaction,
    #[error("escrow account does not match frozen setup")]
    InvalidState,
    #[error("vault account does not match frozen setup")]
    InvalidVault,
    #[error("program attestation failed")]
    ProgramAttestation,
    #[error("claim secret does not match cross-curve setup")]
    InvalidSecret,
    #[error("finalized depth below frozen policy")]
    InsufficientDepth,
}

pub struct SolanaSettlementObserver<R> {
    pool: SolanaRpcPool<R>,
    setup: ValidatedSolanaSetup,
    profile: SolanaAdapterProfileV1,
    min_confirmations: u32,
    max_rpc_slot_lag: u64,
}

impl<R: SolanaRpc> SolanaSettlementObserver<R> {
    pub fn new(
        pool: SolanaRpcPool<R>,
        setup: ValidatedSolanaSetup,
        profile: SolanaAdapterProfileV1,
        min_confirmations: u32,
    ) -> Result<Self, ObserverError> {
        if min_confirmations == 0 || profile.program_id != setup.program_id() {
            return Err(ObserverError::InvalidState);
        }
        Ok(Self {
            pool,
            setup,
            profile,
            min_confirmations,
            max_rpc_slot_lag: 64,
        })
    }

    pub fn observe(
        &self,
        signature: SolanaSignature,
        kind: ObservationKind,
    ) -> Result<SolanaEvidenceEnvelopeV1, ObserverError> {
        let status = self
            .pool
            .signature_status(signature)
            .map_err(map_quorum)?
            .ok_or(ObserverError::NotFinalized)?;
        if status.failed || status.confirmation != Commitment::Finalized {
            return Err(ObserverError::NotFinalized);
        }
        let tip = self
            .pool
            .finalized_tip_floor(self.max_rpc_slot_lag)
            .map_err(map_quorum)?;
        let depth = tip.saturating_sub(status.slot).saturating_add(1);
        if depth < u64::from(self.min_confirmations) {
            return Err(ObserverError::InsufficientDepth);
        }
        let transaction = self
            .pool
            .transaction(signature, Commitment::Finalized)
            .map_err(map_quorum)?
            .ok_or(ObserverError::InvalidTransaction)?;
        if !transaction.success
            || transaction.slot != status.slot
            || transaction.signature != signature
        {
            return Err(ObserverError::InvalidTransaction);
        }
        let anchor = self.pool.block_anchor(status.slot).map_err(map_quorum)?;
        let (instruction_index, instruction) = transaction
            .instructions
            .iter()
            .enumerate()
            .find(|(_, instruction)| {
                instruction.program_id == self.setup.program_id()
                    && instruction.accounts.first() == Some(&self.setup.state_pda())
            })
            .ok_or(ObserverError::InvalidTransaction)?;
        let decoded = EscrowInstructionV1::decode(&instruction.data)
            .map_err(|_| ObserverError::InvalidTransaction)?;
        let state_account = self
            .pool
            .account(self.setup.state_pda(), Commitment::Finalized)
            .map_err(map_quorum)?
            .ok_or(ObserverError::InvalidState)?;
        let state = validate_state_account(&state_account, &self.setup)?;
        let attestation = attest_program(&self.pool, &self.profile, &self.setup)?;
        let vault = self
            .pool
            .account(self.setup.vault_pda(), Commitment::Finalized)
            .map_err(map_quorum)?;
        let vault_hash = validate_vault(vault.as_ref(), &state, &self.setup, kind)?;
        let instruction_index =
            u16::try_from(instruction_index).map_err(|_| ObserverError::InvalidTransaction)?;
        let state_hash = state_hash(&state_account.data);
        let mint = self.setup.asset().mint();
        let body = match (kind, decoded) {
            (ObservationKind::Funding, EscrowInstructionV1::Fund) => {
                if !matches!(
                    state.status,
                    EscrowStatus::Funded | EscrowStatus::Claimed | EscrowStatus::Refunded
                ) {
                    return Err(ObserverError::InvalidState);
                }
                SolanaEvidenceBodyV1::Funding(SolanaFundingEvidenceV1 {
                    settlement_id: self.setup.settlement_id(),
                    terms_hash: self.setup.terms_hash(),
                    program_id: self.setup.program_id(),
                    state_pda: self.setup.state_pda(),
                    vault_pda: self.setup.vault_pda(),
                    signature,
                    instruction_index,
                    slot: status.slot,
                    blockhash: anchor.blockhash,
                    amount: self.setup.amount(),
                    mint,
                    state_hash,
                    vault_hash,
                    program_data_hash: attestation.code_hash,
                })
            }
            (ObservationKind::Claim, EscrowInstructionV1::Claim { revealed_secret_be }) => {
                if state.status != EscrowStatus::Claimed
                    || state.revealed_secret_be != revealed_secret_be
                {
                    return Err(ObserverError::InvalidState);
                }
                revealed_dom_secret_to_xmr_scalar(revealed_secret_be, &self.setup.claim())
                    .map_err(|_| ObserverError::InvalidSecret)?;
                SolanaEvidenceBodyV1::Claim(SolanaClaimEvidenceV1 {
                    settlement_id: self.setup.settlement_id(),
                    terms_hash: self.setup.terms_hash(),
                    program_id: self.setup.program_id(),
                    state_pda: self.setup.state_pda(),
                    vault_pda: self.setup.vault_pda(),
                    signature,
                    instruction_index,
                    slot: status.slot,
                    blockhash: anchor.blockhash,
                    amount: self.setup.amount(),
                    mint,
                    revealed_secret_be,
                    terminal_state_hash: state_hash,
                    vault_hash,
                    program_data_hash: attestation.code_hash,
                })
            }
            (ObservationKind::Refund, EscrowInstructionV1::Refund) => {
                if state.status != EscrowStatus::Refunded || state.revealed_secret_be != [0; 32] {
                    return Err(ObserverError::InvalidState);
                }
                SolanaEvidenceBodyV1::Refund(SolanaRefundEvidenceV1 {
                    settlement_id: self.setup.settlement_id(),
                    terms_hash: self.setup.terms_hash(),
                    program_id: self.setup.program_id(),
                    state_pda: self.setup.state_pda(),
                    vault_pda: self.setup.vault_pda(),
                    signature,
                    instruction_index,
                    slot: status.slot,
                    blockhash: anchor.blockhash,
                    amount: self.setup.amount(),
                    mint,
                    terminal_state_hash: state_hash,
                    vault_hash,
                    program_data_hash: attestation.code_hash,
                })
            }
            _ => return Err(ObserverError::InvalidTransaction),
        };
        let envelope = SolanaEvidenceEnvelopeV1 {
            version: EVIDENCE_VERSION,
            body,
        };
        envelope
            .validate()
            .map_err(|_| ObserverError::InvalidTransaction)?;
        Ok(envelope)
    }
}

fn attest_program<R: SolanaRpc>(
    pool: &SolanaRpcPool<R>,
    profile: &SolanaAdapterProfileV1,
    setup: &ValidatedSolanaSetup,
) -> Result<ProgramAttestation, ObserverError> {
    if profile.require_immutable_program {
        attest_immutable_program(pool, setup.program_id(), setup.program_data_hash())
            .map_err(|_| ObserverError::ProgramAttestation)
    } else {
        Ok(ProgramAttestation {
            program_id: setup.program_id(),
            program_data_address: SolanaPubkey([1; 32]),
            deployment_slot: 0,
            code_hash: setup.program_data_hash(),
            observed_context_slot: 0,
        })
    }
}

fn validate_state_account(
    account: &SolanaAccountSnapshot,
    setup: &ValidatedSolanaSetup,
) -> Result<EscrowStateV1, ObserverError> {
    if account.owner != setup.program_id() || account.executable || account.data.len() != STATE_LEN
    {
        return Err(ObserverError::InvalidState);
    }
    let state = EscrowStateV1::decode(&account.data).map_err(|_| ObserverError::InvalidState)?;
    let expected_asset = match setup.asset() {
        SolanaAssetV1::NativeSol => AssetKind::NativeSol,
        SolanaAssetV1::LegacySpl { .. } => AssetKind::LegacySpl,
    };
    if state.asset_kind != expected_asset
        || state.settlement_id != setup.settlement_id()
        || state.terms_hash != setup.terms_hash()
        || state.setup_id != setup.setup_id()
        || state.funder != setup.funder().0
        || state.recipient != setup.recipient().0
        || state.refund_recipient != setup.refund_recipient().0
        || state.vault != setup.vault_pda().0
        || state.dom_adaptor_point != setup.claim().secp_compressed
        || state.claim_point_ed25519 != setup.claim().ed_compressed
        || state.amount != setup.amount()
        || state.refund_after_unix != setup.refund_after_unix()
        || state.mint != setup.asset().mint().0
        || state.token_program != setup.asset().token_program().0
        || state.token_decimals != setup.asset().decimals()
    {
        return Err(ObserverError::InvalidState);
    }
    Ok(state)
}

fn validate_vault(
    account: Option<&SolanaAccountSnapshot>,
    state: &EscrowStateV1,
    setup: &ValidatedSolanaSetup,
    kind: ObservationKind,
) -> Result<[u8; 32], ObserverError> {
    let account = account.ok_or(ObserverError::InvalidVault)?;
    match setup.asset() {
        SolanaAssetV1::NativeSol => {
            if account.owner != setup.program_id() || account.executable || !account.data.is_empty()
            {
                return Err(ObserverError::InvalidVault);
            }
            if kind == ObservationKind::Funding
                && state.status == EscrowStatus::Funded
                && account.lamports < setup.amount()
            {
                return Err(ObserverError::InvalidVault);
            }
        }
        SolanaAssetV1::LegacySpl { mint, .. } => {
            if account.owner != setup.asset().token_program() || account.executable {
                return Err(ObserverError::InvalidVault);
            }
            let token = LegacyTokenAccount::decode(&account.data)
                .map_err(|_| ObserverError::InvalidVault)?;
            if token.mint != mint || token.authority != setup.vault_authority() {
                return Err(ObserverError::InvalidVault);
            }
            if kind == ObservationKind::Funding
                && state.status == EscrowStatus::Funded
                && token.amount != setup.amount()
            {
                return Err(ObserverError::InvalidVault);
            }
            if matches!(kind, ObservationKind::Claim | ObservationKind::Refund) && token.amount != 0
            {
                return Err(ObserverError::InvalidVault);
            }
        }
    }
    Ok(account.commitment_hash())
}

fn state_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-INTEROP/SOLANA-ESCROW-STATE/V1\0");
    hasher.update(data);
    hasher.finalize().into()
}

fn map_quorum(_: QuorumError) -> ObserverError {
    ObserverError::Quorum
}
