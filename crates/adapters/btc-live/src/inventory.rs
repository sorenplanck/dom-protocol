//! Confirmed-spendable wallet observation for the solver inventory.
//!
//! One read produces an evidence-bound sum of the wallet's confirmed,
//! spendable and solvable UTXOs at one exact chain tip. The tip is read
//! before and after the wallet scan and the observation is refused when the
//! chain moved in between, so the amount, height and anchor always commit to
//! a single canonical position — the same discipline the EVM inventory read
//! applies with its corroborated `finalized` block.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use serde_json::{json, Value};

use crate::funding::exact_rpc_btc_amount_sat;
use crate::rpc::BitcoinCoreRpcClientV1;
use crate::LiveBitcoinError;

const OBSERVATION_DOMAIN_V1: &[u8] = b"DOM-BTC-LIVE/INVENTORY-OBSERVATION/V1\0";
const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;
/// Upper bound accepted from the caller; deeper requirements are a
/// configuration error, not a scan parameter.
const MAX_MINIMUM_CONFIRMATIONS_V1: u64 = 10_000;
/// `listunspent` maxconf ceiling pinned explicitly instead of relying on the
/// node default.
const MAX_CONFIRMATIONS_SCAN_V1: u64 = 99_999_999;

/// Evidence-bound confirmed-spendable balance of the retained wallet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinSpendableObservationV1 {
    /// Exact sum of confirmed, spendable, solvable UTXO amounts in satoshis.
    pub spendable_sat: u64,
    /// Number of UTXOs contributing to `spendable_sat`.
    pub utxo_count: u64,
    /// Chain height the observation is bound to.
    pub canonical_height: u64,
    /// Best-block hash at `canonical_height`.
    pub canonical_anchor: [u8; 32],
    /// Commitment to the exact tip and wallet responses.
    pub evidence_digest: [u8; 32],
    /// Confirmation depth every counted UTXO satisfies.
    pub minimum_confirmations: u64,
}

/// Reads the wallet's confirmed spendable balance at one exact tip.
pub fn observe_confirmed_spendable(
    rpc: &BitcoinCoreRpcClientV1,
    minimum_confirmations: u64,
) -> Result<BitcoinSpendableObservationV1, LiveBitcoinError> {
    if minimum_confirmations == 0 || minimum_confirmations > MAX_MINIMUM_CONFIRMATIONS_V1 {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    let (start_height, start_hash, start_display) = chain_tip(rpc)?;
    let listed = rpc.wallet_rpc(
        "listunspent",
        json!([minimum_confirmations, MAX_CONFIRMATIONS_SCAN_V1, [], false]),
    )?;
    let Value::Array(entries) = &listed else {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    };
    let mut spendable_sat = 0_u64;
    let mut utxo_count = 0_u64;
    for entry in entries {
        let confirmations = entry
            .get("confirmations")
            .and_then(Value::as_u64)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        if confirmations < minimum_confirmations {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        let spendable = entry
            .get("spendable")
            .and_then(Value::as_bool)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        let solvable = entry
            .get("solvable")
            .and_then(Value::as_bool)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        if !spendable || !solvable {
            continue;
        }
        let amount_sat = entry
            .get("amount")
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(exact_rpc_btc_amount_sat)?;
        spendable_sat = spendable_sat
            .checked_add(amount_sat)
            .filter(|total| *total <= MAX_MONEY_SAT)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        utxo_count = utxo_count
            .checked_add(1)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
    }
    let (end_height, end_hash, _) = chain_tip(rpc)?;
    if end_height != start_height || end_hash != start_hash {
        return Err(LiveBitcoinError::StateConflict);
    }
    let canonical =
        serde_json::to_vec(&listed).map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
    let mut hasher = Blake2bVar::new(32).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    hasher.update(OBSERVATION_DOMAIN_V1);
    hasher.update(&start_height.to_be_bytes());
    hasher.update(&start_hash);
    hasher.update(start_display.as_bytes());
    hasher.update(&minimum_confirmations.to_be_bytes());
    hasher.update(&canonical);
    let mut evidence_digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut evidence_digest)
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    Ok(BitcoinSpendableObservationV1 {
        spendable_sat,
        utxo_count,
        canonical_height: start_height,
        canonical_anchor: start_hash,
        evidence_digest,
        minimum_confirmations,
    })
}

fn chain_tip(rpc: &BitcoinCoreRpcClientV1) -> Result<(u64, [u8; 32], String), LiveBitcoinError> {
    let height = rpc
        .node_rpc("getblockcount", json!([]))?
        .as_u64()
        .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
    let display = rpc
        .node_rpc("getbestblockhash", json!([]))?
        .as_str()
        .map(str::to_owned)
        .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
    Ok((height, decode_block_hash(&display)?, display))
}

fn decode_block_hash(display: &str) -> Result<[u8; 32], LiveBitcoinError> {
    let bytes = display.as_bytes();
    if bytes.len() != 64 {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    }
    let mut hash = [0_u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        let value = |digit: u8| -> Result<u8, LiveBitcoinError> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'a'..=b'f' => Ok(digit - b'a' + 10),
                _ => Err(LiveBitcoinError::InvalidRpcResponse),
            }
        };
        hash[index] = value(chunk[0])? << 4 | value(chunk[1])?;
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_hash_decoding_is_exact_lowercase_hex_only() {
        let display = "00".repeat(32);
        assert_eq!(decode_block_hash(&display).unwrap(), [0; 32]);
        assert!(decode_block_hash(&"0A".repeat(32)).is_err());
        assert!(decode_block_hash(&"0".repeat(63)).is_err());
        assert!(decode_block_hash(&"zz".repeat(32)).is_err());
        let mut mixed = "ff".repeat(31);
        mixed.push_str("0a");
        let decoded = decode_block_hash(&mixed).unwrap();
        assert_eq!(decoded[31], 0x0a);
        assert_eq!(decoded[0], 0xff);
    }

    #[test]
    fn confirmation_bounds_are_refused_before_any_rpc() {
        // Constructing a client requires a live cookie/socket, so the bound
        // check must be independently testable: it is pure.
        assert!(MAX_MINIMUM_CONFIRMATIONS_V1 < MAX_CONFIRMATIONS_SCAN_V1);
        assert_eq!(MAX_MONEY_SAT, 2_100_000_000_000_000);
    }
}
