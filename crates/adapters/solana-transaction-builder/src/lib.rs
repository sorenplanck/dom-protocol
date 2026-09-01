//! Deterministic legacy Solana message construction with external signing.
//!
//! The adapter never owns a user's signing key. It freezes exact message bytes,
//! verifies externally supplied Ed25519 signatures, then assembles exact wire
//! bytes for durable delivery.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use solana_types::{SolanaHash, SolanaInstruction, SolanaPubkey, SolanaSignature};

/// Solana's IPv6 MTU-derived packet data limit.
pub const PACKET_DATA_SIZE: usize = 1_232;
/// Legacy messages index accounts with a single byte.
pub const MAX_ACCOUNT_KEYS: usize = 256;

/// Message/transaction construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransactionBuildError {
    #[error("empty instruction list")]
    EmptyInstructions,
    #[error("invalid or excessive account list")]
    AccountBounds,
    #[error("missing or invalid signer")]
    SignatureInvalid,
    #[error("duplicate signer with divergent signature")]
    SignatureConflict,
    #[error("serialized transaction exceeds Solana packet bound")]
    PacketTooLarge,
    #[error("compact length exceeds supported bound")]
    LengthBounds,
}

/// Exact legacy message and ordered signer set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMessagePlan {
    /// Exact bytes signed by each signer.
    pub message: Vec<u8>,
    /// Ordered account keys encoded by the message.
    pub account_keys: Vec<SolanaPubkey>,
    /// Prefix of account keys which must sign.
    pub signer_keys: Vec<SolanaPubkey>,
}

#[derive(Debug, Clone, Copy)]
struct AggregatedMeta {
    key: SolanaPubkey,
    signer: bool,
    writable: bool,
    first_seen: usize,
    is_program: bool,
}

/// Build a deterministic legacy message.
pub fn build_legacy_message(
    fee_payer: SolanaPubkey,
    recent_blockhash: SolanaHash,
    instructions: &[SolanaInstruction],
) -> Result<LegacyMessagePlan, TransactionBuildError> {
    if fee_payer.is_zero() || instructions.is_empty() {
        return Err(TransactionBuildError::EmptyInstructions);
    }
    let mut map: BTreeMap<SolanaPubkey, AggregatedMeta> = BTreeMap::new();
    let mut sequence = 0usize;
    merge_meta(&mut map, fee_payer, true, true, false, sequence);
    sequence += 1;
    for instruction in instructions {
        if instruction.program_id.is_zero() {
            return Err(TransactionBuildError::AccountBounds);
        }
        for meta in &instruction.accounts {
            merge_meta(
                &mut map,
                meta.pubkey,
                meta.is_signer,
                meta.is_writable,
                false,
                sequence,
            );
            sequence += 1;
        }
        merge_meta(
            &mut map,
            instruction.program_id,
            false,
            false,
            true,
            sequence,
        );
        sequence += 1;
    }
    if map.len() > MAX_ACCOUNT_KEYS {
        return Err(TransactionBuildError::AccountBounds);
    }

    let payer = map
        .remove(&fee_payer)
        .ok_or(TransactionBuildError::AccountBounds)?;
    let mut metas: Vec<AggregatedMeta> = map.into_values().collect();
    metas.sort_by_key(|meta| {
        let group = match (meta.signer, meta.writable) {
            (true, true) => 0u8,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        };
        (group, meta.first_seen)
    });
    let mut ordered = Vec::with_capacity(metas.len() + 1);
    ordered.push(payer);
    ordered.extend(metas);

    let account_keys: Vec<SolanaPubkey> = ordered.iter().map(|meta| meta.key).collect();
    let signer_keys: Vec<SolanaPubkey> = ordered
        .iter()
        .take_while(|meta| meta.signer)
        .map(|meta| meta.key)
        .collect();
    let num_required_signatures =
        u8::try_from(signer_keys.len()).map_err(|_| TransactionBuildError::AccountBounds)?;
    let num_readonly_signed_accounts = u8::try_from(
        ordered
            .iter()
            .filter(|meta| meta.signer && !meta.writable)
            .count(),
    )
    .map_err(|_| TransactionBuildError::AccountBounds)?;
    let num_readonly_unsigned_accounts = u8::try_from(
        ordered
            .iter()
            .filter(|meta| !meta.signer && !meta.writable)
            .count(),
    )
    .map_err(|_| TransactionBuildError::AccountBounds)?;

    let indices: BTreeMap<SolanaPubkey, u8> = account_keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            u8::try_from(index)
                .map(|index| (*key, index))
                .map_err(|_| TransactionBuildError::AccountBounds)
        })
        .collect::<Result<_, _>>()?;

    let mut message = Vec::new();
    message.extend_from_slice(&[
        num_required_signatures,
        num_readonly_signed_accounts,
        num_readonly_unsigned_accounts,
    ]);
    put_short_len(&mut message, account_keys.len())?;
    for key in &account_keys {
        message.extend_from_slice(&key.0);
    }
    message.extend_from_slice(&recent_blockhash.0);
    put_short_len(&mut message, instructions.len())?;
    for instruction in instructions {
        let program_index = *indices
            .get(&instruction.program_id)
            .ok_or(TransactionBuildError::AccountBounds)?;
        message.push(program_index);
        put_short_len(&mut message, instruction.accounts.len())?;
        for account in &instruction.accounts {
            message.push(
                *indices
                    .get(&account.pubkey)
                    .ok_or(TransactionBuildError::AccountBounds)?,
            );
        }
        put_short_len(&mut message, instruction.data.len())?;
        message.extend_from_slice(&instruction.data);
    }
    Ok(LegacyMessagePlan {
        message,
        account_keys,
        signer_keys,
    })
}

/// Verify external signatures and assemble exact transaction wire bytes.
pub fn assemble_signed_transaction(
    plan: &LegacyMessagePlan,
    signatures: &[(SolanaPubkey, SolanaSignature)],
) -> Result<Vec<u8>, TransactionBuildError> {
    if signatures.len() != plan.signer_keys.len() {
        return Err(TransactionBuildError::SignatureInvalid);
    }
    let provided: BTreeMap<SolanaPubkey, SolanaSignature> =
        signatures
            .iter()
            .try_fold(BTreeMap::new(), |mut map, (key, signature)| {
                if let Some(existing) = map.insert(*key, *signature) {
                    if existing != *signature {
                        return Err(TransactionBuildError::SignatureConflict);
                    }
                }
                Ok(map)
            })?;
    let mut ordered_signatures = Vec::with_capacity(plan.signer_keys.len());
    for signer in &plan.signer_keys {
        let signature = *provided
            .get(signer)
            .ok_or(TransactionBuildError::SignatureInvalid)?;
        verify_signature(*signer, signature, &plan.message)?;
        ordered_signatures.push(signature);
    }
    let mut transaction = Vec::new();
    put_short_len(&mut transaction, ordered_signatures.len())?;
    for signature in ordered_signatures {
        transaction.extend_from_slice(&signature.0);
    }
    transaction.extend_from_slice(&plan.message);
    if transaction.len() > PACKET_DATA_SIZE {
        return Err(TransactionBuildError::PacketTooLarge);
    }
    Ok(transaction)
}

/// Return the primary transaction signature.
pub fn primary_signature(
    plan: &LegacyMessagePlan,
    signatures: &[(SolanaPubkey, SolanaSignature)],
) -> Result<SolanaSignature, TransactionBuildError> {
    let primary = *plan
        .signer_keys
        .first()
        .ok_or(TransactionBuildError::SignatureInvalid)?;
    signatures
        .iter()
        .find_map(|(key, signature)| (*key == primary).then_some(*signature))
        .ok_or(TransactionBuildError::SignatureInvalid)
}

fn merge_meta(
    map: &mut BTreeMap<SolanaPubkey, AggregatedMeta>,
    key: SolanaPubkey,
    signer: bool,
    writable: bool,
    is_program: bool,
    first_seen: usize,
) {
    map.entry(key)
        .and_modify(|meta| {
            meta.signer |= signer;
            if !meta.is_program {
                meta.writable |= writable;
            }
            meta.is_program |= is_program;
            if meta.is_program {
                meta.writable = false;
                meta.signer = false;
            }
        })
        .or_insert(AggregatedMeta {
            key,
            signer: signer && !is_program,
            writable: writable && !is_program,
            first_seen,
            is_program,
        });
}

fn verify_signature(
    key: SolanaPubkey,
    signature: SolanaSignature,
    message: &[u8],
) -> Result<(), TransactionBuildError> {
    let verifying_key =
        VerifyingKey::from_bytes(&key.0).map_err(|_| TransactionBuildError::SignatureInvalid)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(&signature.0))
        .map_err(|_| TransactionBuildError::SignatureInvalid)
}

fn put_short_len(output: &mut Vec<u8>, mut value: usize) -> Result<(), TransactionBuildError> {
    if value > 0xffff {
        return Err(TransactionBuildError::LengthBounds);
    }
    loop {
        let low = u8::try_from(value & 0x7f).map_err(|_| TransactionBuildError::LengthBounds)?;
        value >>= 7;
        if value == 0 {
            output.push(low);
            return Ok(());
        }
        output.push(low | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use solana_types::SolanaAccountMeta;

    use super::*;

    #[test]
    fn external_signature_round_trip() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let payer = SolanaPubkey(signing.verifying_key().to_bytes());
        let instruction = SolanaInstruction {
            program_id: SolanaPubkey([9; 32]),
            accounts: vec![SolanaAccountMeta {
                pubkey: payer,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![1, 2, 3],
        };
        let plan = build_legacy_message(payer, SolanaHash([4; 32]), &[instruction]).unwrap();
        let signature = SolanaSignature(signing.sign(&plan.message).to_bytes());
        let transaction = assemble_signed_transaction(&plan, &[(payer, signature)]).unwrap();
        assert!(transaction.len() <= PACKET_DATA_SIZE);
        assert_eq!(
            primary_signature(&plan, &[(payer, signature)]).unwrap(),
            signature
        );
    }
}
