//! Bitcoin transaction templates and SIGHASH_DEFAULT (Annex M M.3).
//!
//! A template is *frozen*: once built, every input, output, amount,
//! prevout and the annex-absence are fixed, and the key-path claim
//! sighash is `TapSighash(SIGHASH_DEFAULT)` over exactly those bytes. Any
//! change requires a new session and a new nonce (M.3.3) — this module
//! only builds and hashes; it never mutates a frozen template in place.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::types::BitcoinNetworkV1;

const FROZEN_TEMPLATE_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F5/V1/FROZEN-TEMPLATE\0";

/// A previous output being spent (M.3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinPrevoutV1 {
    /// The outpoint (txid || vout).
    pub txid: [u8; 32],
    /// The output index.
    pub vout: u32,
    /// The amount locked, in satoshis.
    pub amount_sat: u64,
    /// The exact scriptPubKey of the prevout.
    pub script_pubkey: Vec<u8>,
}

/// A transaction input in canonical Bitcoin wire form (M.3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinTxInV1 {
    /// Spent outpoint txid (internal byte order).
    pub txid: [u8; 32],
    /// Spent outpoint index.
    pub vout: u32,
    /// nSequence (carries the CSV value on the refund input).
    pub sequence: u32,
}

/// A transaction output (M.3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinTxOutV1 {
    /// Amount in satoshis.
    pub amount_sat: u64,
    /// scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// A frozen, unsigned Bitcoin transaction plus its committed prevouts and
/// key-path sighash (M.3.1). `nVersion ≥ 2` and `nLockTime` are fixed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrozenBitcoinTemplateV1 {
    /// Codec version of this frozen template.
    pub codec_version: u16,
    /// The network this template belongs to (identity is committed
    /// elsewhere via the genesis hash of the binding).
    pub network: BitcoinNetworkV1,
    /// Transaction version (≥ 2, required for BIP68 on the refund).
    pub version: i32,
    /// Absolute lock time (0 for the claim/refund of v3.2).
    pub lock_time: u32,
    /// The ordered inputs.
    pub inputs: Vec<BitcoinTxInV1>,
    /// The ordered outputs.
    pub outputs: Vec<BitcoinTxOutV1>,
    /// The committed prevouts, one per input, in input order.
    pub prevouts: Vec<BitcoinPrevoutV1>,
}

/// Which input of the template is the contractual (P2TR) input.
pub const CONTRACT_INPUT_INDEX: u32 = 0;

/// Template construction / validation failures.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TemplateError {
    /// `version` was below 2 (BIP68 requires ≥ 2 for the refund).
    #[error("transaction version below 2")]
    VersionTooLow,
    /// The template had no inputs or the prevout count did not match.
    #[error("input/prevout count mismatch")]
    InputPrevoutMismatch,
    /// The template had no outputs.
    #[error("no outputs")]
    NoOutputs,
    /// A satoshi amount exceeded the 21e14 supply cap.
    #[error("amount exceeds supply cap")]
    AmountOverflow,
    /// A vector or script length cannot be represented by the frozen codec.
    #[error("frozen template encoding exceeds its bound")]
    EncodingOverflow,
    /// The fixed-size digest backend rejected its frozen output size.
    #[error("frozen template digest backend unavailable")]
    DigestUnavailable,
}

/// The maximum number of satoshis that can ever exist (21e6 BTC).
pub const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;

impl FrozenBitcoinTemplateV1 {
    /// Validates the structural invariants of a frozen template (M.3.1):
    /// version ≥ 2, one prevout per input, at least one output, amounts
    /// within the supply cap.
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.version < 2 {
            return Err(TemplateError::VersionTooLow);
        }
        if self.inputs.is_empty() || self.inputs.len() != self.prevouts.len() {
            return Err(TemplateError::InputPrevoutMismatch);
        }
        if self.outputs.is_empty() {
            return Err(TemplateError::NoOutputs);
        }
        for out in &self.outputs {
            if out.amount_sat > MAX_MONEY_SAT {
                return Err(TemplateError::AmountOverflow);
            }
        }
        for prev in &self.prevouts {
            if prev.amount_sat > MAX_MONEY_SAT {
                return Err(TemplateError::AmountOverflow);
            }
        }
        Ok(())
    }
}

/// Computes the canonical F5 commitment to one validated frozen template.
///
/// The encoding and domain are the same bytes consumed by the durable F5
/// claim path.  Keeping the function in the Bitcoin adapter lets a live
/// wallet commit its funding, claim, and refund templates before the route
/// manifest exists without reimplementing the frozen codec in an executor.
pub fn frozen_template_digest_v1(
    template: &FrozenBitcoinTemplateV1,
) -> Result<[u8; 32], TemplateError> {
    template.validate()?;
    let input_count =
        u32::try_from(template.inputs.len()).map_err(|_| TemplateError::EncodingOverflow)?;
    let output_count =
        u32::try_from(template.outputs.len()).map_err(|_| TemplateError::EncodingOverflow)?;
    let prevout_count =
        u32::try_from(template.prevouts.len()).map_err(|_| TemplateError::EncodingOverflow)?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(FROZEN_TEMPLATE_DIGEST_DOMAIN);
    bytes.extend_from_slice(&template.codec_version.to_be_bytes());
    bytes.push(template.network as u8);
    bytes.extend_from_slice(&template.version.to_be_bytes());
    bytes.extend_from_slice(&template.lock_time.to_be_bytes());
    bytes.extend_from_slice(&input_count.to_be_bytes());
    for input in &template.inputs {
        bytes.extend_from_slice(&input.txid);
        bytes.extend_from_slice(&input.vout.to_be_bytes());
        bytes.extend_from_slice(&input.sequence.to_be_bytes());
    }
    bytes.extend_from_slice(&output_count.to_be_bytes());
    for output in &template.outputs {
        let script_len = u32::try_from(output.script_pubkey.len())
            .map_err(|_| TemplateError::EncodingOverflow)?;
        bytes.extend_from_slice(&output.amount_sat.to_be_bytes());
        bytes.extend_from_slice(&script_len.to_be_bytes());
        bytes.extend_from_slice(&output.script_pubkey);
    }
    bytes.extend_from_slice(&prevout_count.to_be_bytes());
    for prevout in &template.prevouts {
        let script_len = u32::try_from(prevout.script_pubkey.len())
            .map_err(|_| TemplateError::EncodingOverflow)?;
        bytes.extend_from_slice(&prevout.txid);
        bytes.extend_from_slice(&prevout.vout.to_be_bytes());
        bytes.extend_from_slice(&prevout.amount_sat.to_be_bytes());
        bytes.extend_from_slice(&script_len.to_be_bytes());
        bytes.extend_from_slice(&prevout.script_pubkey);
    }

    let mut hasher = Blake2bVar::new(32).map_err(|_| TemplateError::DigestUnavailable)?;
    hasher.update(&bytes);
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| TemplateError::DigestUnavailable)?;
    Ok(digest)
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn frozen_digest_commits_every_template_class() -> Result<(), TemplateError> {
        let base = FrozenBitcoinTemplateV1 {
            codec_version: 1,
            network: BitcoinNetworkV1::Regtest,
            version: 2,
            lock_time: 0,
            inputs: vec![BitcoinTxInV1 {
                txid: [1; 32],
                vout: 2,
                sequence: 0xffff_fffd,
            }],
            outputs: vec![BitcoinTxOutV1 {
                amount_sat: 90_000,
                script_pubkey: vec![0x51, 0x20, 3, 4],
            }],
            prevouts: vec![BitcoinPrevoutV1 {
                txid: [1; 32],
                vout: 2,
                amount_sat: 100_000,
                script_pubkey: vec![0x51, 0x20, 5, 6],
            }],
        };
        let first = frozen_template_digest_v1(&base)?;
        let mut changed = base.clone();
        changed.inputs[0].sequence = 7;
        assert_ne!(first, frozen_template_digest_v1(&changed)?);
        changed = base.clone();
        changed.outputs[0].script_pubkey.push(8);
        assert_ne!(first, frozen_template_digest_v1(&changed)?);
        changed = base;
        changed.prevouts[0].amount_sat += 1;
        assert_ne!(first, frozen_template_digest_v1(&changed)?);
        Ok(())
    }
}
