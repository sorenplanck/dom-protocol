//! Independent MIT Monero parser/hash check for sidecar-produced raw transactions.

#![forbid(unsafe_code)]

use blake2::{digest::consts::U32, Blake2b, Digest};
use monero_oxide::transaction::{NotPruned, Transaction};

type Blake2b256 = Blake2b<U32>;
/// Hard raw transaction bound.
pub const MAX_VERIFIED_RAW_TX_BYTES: usize = 1024 * 1024;

/// Raw transaction validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RawTxError {
    /// Empty/oversized bytes.
    #[error("raw transaction exceeds bounds")]
    BoundsExceeded,
    /// Monero parser rejected bytes.
    #[error("invalid raw Monero transaction")]
    Parse,
    /// Bytes are not the canonical serialization of the parsed transaction.
    #[error("non-canonical raw Monero transaction")]
    NonCanonical,
    /// Parsed consensus hash differs from the sidecar response.
    #[error("Monero transaction hash mismatch")]
    HashMismatch,
}

/// Independently verified public result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRawTransaction {
    /// Consensus transaction hash.
    pub tx_hash: [u8; 32],
    /// Domain-separated exact-byte fingerprint.
    pub raw_fingerprint: [u8; 32],
}

/// Parse, require full consumption/canonical roundtrip, and verify consensus hash.
pub fn verify_exact_raw_transaction(
    raw: &[u8],
    expected_tx_hash: [u8; 32],
) -> Result<VerifiedRawTransaction, RawTxError> {
    if raw.is_empty() || raw.len() > MAX_VERIFIED_RAW_TX_BYTES || expected_tx_hash == [0; 32] {
        return Err(RawTxError::BoundsExceeded);
    }
    let mut cursor = raw;
    let transaction: Transaction<NotPruned> =
        Transaction::read(&mut cursor).map_err(|_| RawTxError::Parse)?;
    if !cursor.is_empty() {
        return Err(RawTxError::NonCanonical);
    }
    let canonical = transaction.serialize();
    if canonical.as_slice() != raw {
        return Err(RawTxError::NonCanonical);
    }
    let tx_hash = transaction.hash();
    if tx_hash != expected_tx_hash {
        return Err(RawTxError::HashMismatch);
    }
    let raw_fingerprint = Blake2b256::new()
        .chain_update(b"DOM-INTEROP/XMR-RAW-TX/V1\0")
        .chain_update(raw)
        .finalize()
        .into();
    Ok(VerifiedRawTransaction {
        tx_hash,
        raw_fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_oversized_and_unbound_inputs_are_refused_before_parsing() {
        assert_eq!(
            verify_exact_raw_transaction(&[], [1; 32]).unwrap_err(),
            RawTxError::BoundsExceeded
        );
        let oversized = vec![0_u8; MAX_VERIFIED_RAW_TX_BYTES + 1];
        assert_eq!(
            verify_exact_raw_transaction(&oversized, [1; 32]).unwrap_err(),
            RawTxError::BoundsExceeded
        );
        // A zero expected hash is not a hash: accepting it would let a caller
        // opt out of the comparison entirely.
        assert_eq!(
            verify_exact_raw_transaction(&[1, 2, 3], [0; 32]).unwrap_err(),
            RawTxError::BoundsExceeded
        );
    }

    #[test]
    fn bytes_that_are_not_a_monero_transaction_are_refused() {
        assert_eq!(
            verify_exact_raw_transaction(b"not a monero transaction", [1; 32]).unwrap_err(),
            RawTxError::Parse
        );
    }
}
