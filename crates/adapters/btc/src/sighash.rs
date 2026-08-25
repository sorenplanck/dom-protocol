//! BIP341 key-path sighash with SIGHASH_DEFAULT (Annex M M.3.3).
//!
//! The claim uses the Taproot key-path with `SIGHASH_DEFAULT` (implicit
//! 0x00), a 64-byte witness (no appended sighash byte), no annex, and
//! prevout amounts and scriptPubKeys committed. Computing this hash by
//! hand would be reimplementing Taproot (forbidden by M.0.4 and less safe
//! than a reviewed implementation), so the audited `bitcoin` crate does
//! it; this module only marshals our frozen template into it and enforces
//! the F5 restrictions (all prevouts present, one per input).

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::templates::{FrozenBitcoinTemplateV1, TemplateError};

/// Errors specific to sighash computation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SighashError {
    /// The template failed structural validation.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// The contract input index is out of range.
    #[error("contract input index out of range")]
    InputIndexOutOfRange,
    /// The `bitcoin` crate rejected the sighash computation.
    #[error("sighash computation failed")]
    ComputationFailed,
}

/// Marshals a frozen template into a rust-bitcoin `Transaction`.
///
/// Witnesses are empty (the template is unsigned); nVersion and nLockTime
/// come straight from the frozen fields.
fn to_bitcoin_tx(template: &FrozenBitcoinTemplateV1) -> Transaction {
    let input = template
        .inputs
        .iter()
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(i.txid)),
                vout: i.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(i.sequence),
            witness: Witness::new(),
        })
        .collect();
    let output = template
        .outputs
        .iter()
        .map(|o| TxOut {
            value: Amount::from_sat(o.amount_sat),
            script_pubkey: ScriptBuf::from_bytes(o.script_pubkey.clone()),
        })
        .collect();
    Transaction {
        version: Version(template.version),
        lock_time: LockTime::from_consensus(template.lock_time),
        input,
        output,
    }
}

/// Computes the key-path `TapSighash` with `SIGHASH_DEFAULT` for
/// `contract_input_index` of a frozen template (M.3.3). Commits every
/// prevout amount and scriptPubKey; the annex is absent by construction.
pub fn key_path_sighash_default(
    template: &FrozenBitcoinTemplateV1,
    contract_input_index: u32,
) -> Result<[u8; 32], SighashError> {
    template.validate()?;
    let idx = contract_input_index as usize;
    if idx >= template.inputs.len() {
        return Err(SighashError::InputIndexOutOfRange);
    }

    let tx = to_bitcoin_tx(template);
    let prevouts: Vec<TxOut> = template
        .prevouts
        .iter()
        .map(|p| TxOut {
            value: Amount::from_sat(p.amount_sat),
            script_pubkey: ScriptBuf::from_bytes(p.script_pubkey.clone()),
        })
        .collect();

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(idx, &Prevouts::All(&prevouts), TapSighashType::Default)
        .map_err(|_| SighashError::ComputationFailed)?;
    Ok(sighash.to_byte_array())
}
