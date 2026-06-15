//! Central store record types (design §2.4).
//!
//! The wallet v2 store keeps **one persisted record per owned output**
//! ([`StoredOutput`]). Unlike v1's `OwnedOutput` (`dom-wallet/src/types.rs`),
//! which pairs `spent: bool` with removal from the index, v2 carries an explicit
//! [`OutputStatus`] and **never removes** an output that was ever canonical.
//! The blinding factor is **always** persisted — including the random ones
//! (change / receive-slate) — which is exactly the property v1 lacks and the
//! reason behind the WDSF-001/002 fund-loss defects.
//!
//! This sub-step (3A) defines the types and the read surface only. Disk
//! persistence (3C) and reconciliation (3B) live in later sub-steps.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Custom serde for the 33-byte compressed Pedersen commitment.
///
/// `serde` only provides array impls up to length 32, so the 33-byte commitment
/// needs an explicit codec. Ported verbatim from v1 (`dom-wallet/src/types.rs`).
mod serde_commitment {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 33], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(&bytes[..])
    }

    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
        if v.len() != 33 {
            return Err(serde::de::Error::custom("commitment must be 33 bytes"));
        }
        let mut a = [0u8; 33];
        a.copy_from_slice(&v);
        Ok(a)
    }
}

/// Custom serde for the `Zeroizing<[u8; 32]>` blinding factor.
///
/// Keeps v1's 32-byte-bytes representation and `Zeroizing` wrapper (wiped on
/// drop). Ported verbatim from v1 (`dom-wallet/src/types.rs`).
mod serde_blinding {
    use serde::{Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(bytes: &Zeroizing<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&bytes[..])
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("blinding factor must be 32 bytes"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Zeroizing::new(array))
    }
}

/// Where a [`StoredOutput`] came from (design §2.4 `origin`).
///
/// Orthogonal to re-derivability: a `Change` or `ReceiveSlate` output has a
/// random blinding that exists nowhere but the store, while a `Coinbase` output
/// is re-derivable from the seed by height. Retention never depends on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputOrigin {
    /// Wallet-owned coinbase (subject to maturity; derivable by height).
    Coinbase,
    /// Change produced by an outgoing send (`create_send`). Random blinding.
    Change,
    /// Output received via an interactive slate (`receive`). Random blinding.
    ReceiveSlate,
}

/// Output lifecycle state (design §3). Replaces v1's `spent: bool` + index
/// removal pair. **Reservation** (`reserved_for`) is orthogonal and is not a
/// state.
///
/// The legal transitions between these states are defined in
/// [`crate::state`] ([`OutputStatus::can_transition_to`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputStatus {
    /// Exists locally with its blinding written, commitment not yet canonical.
    Unconfirmed,
    /// Commitment is in the canonical output set at `origin_block`.
    Confirmed,
    /// Commitment was consumed as a canonical input.
    Spent,
    /// The origin (and possibly the spend) left the chain in a reorg. Blinding
    /// and value are kept; the output is retained for re-mine recovery.
    Reorged,
}

/// Reference to the block that confirmed an output (design §2.4 `origin_block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRef {
    /// Block height.
    pub height: u64,
    /// 32-byte block hash.
    pub hash: [u8; 32],
}

/// Derivation index, when the blinding is re-derivable from the seed.
///
/// **Metadata only** (design §2.4): traceability for restore-from-seed (§7.4).
/// Retention of an output **never** depends on this being `Some` — that is
/// exactly the v1 bug. `None` for random blindings (change / receive-slate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivIndex {
    /// Coinbase re-derivable by its block height.
    CoinbaseHeight(u64),
    /// Receive-request output re-derivable by its derivation index.
    ReceiveRequest(u32),
}

/// The central persisted record: one per wallet-owned output (design §2.4).
///
/// `commitment` is the primary key. `blinding` is **always** persisted (the
/// fix). Status changes are driven by the state machine in [`crate::state`];
/// the retention invariant **INV-RET** guarantees a `Confirmed`/`Spent`/
/// `Reorged` output is never deleted and never loses its blinding.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredOutput {
    /// Compressed 33-byte Pedersen commitment. **Primary key.**
    #[serde(with = "serde_commitment")]
    pub commitment: [u8; 33],
    /// Value in noms.
    pub value: u64,
    /// 32-byte blinding factor. **Always persisted** (including random ones).
    /// Zeroized on drop.
    #[serde(with = "serde_blinding")]
    pub blinding: Zeroizing<[u8; 32]>,
    /// Provenance of the output.
    pub origin: OutputOrigin,
    /// Lifecycle state (state machine §3).
    pub status: OutputStatus,
    /// Confirming block; `None` while `Unconfirmed`.
    pub origin_block: Option<BlockRef>,
    /// Whether this is a coinbase output (subject to maturity).
    pub is_coinbase: bool,
    /// Derivation index if re-derivable from the seed. Metadata, **not** a
    /// retention condition.
    pub derivable: Option<DerivIndex>,
    /// Slate hash that reserved this output as an input. Orthogonal to `status`.
    pub reserved_for: Option<[u8; 32]>,
    /// Unix ts of local creation.
    pub created_at: u64,
    /// Unix ts of the last transition.
    pub updated_at: u64,
}

impl StoredOutput {
    /// Create a freshly-mined/created output in [`OutputStatus::Unconfirmed`]
    /// with its blinding already written (transition `C0` of §3.1).
    ///
    /// `now` is the caller-supplied unix timestamp (kept as a parameter so the
    /// type stays pure and deterministically testable).
    pub fn new_unconfirmed(
        commitment: [u8; 33],
        value: u64,
        blinding: [u8; 32],
        origin: OutputOrigin,
        is_coinbase: bool,
        derivable: Option<DerivIndex>,
        now: u64,
    ) -> Self {
        Self {
            commitment,
            value,
            blinding: Zeroizing::new(blinding),
            origin,
            status: OutputStatus::Unconfirmed,
            origin_block: None,
            is_coinbase,
            derivable,
            reserved_for: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Whether this output is currently reserved as a slate input.
    pub fn is_reserved(&self) -> bool {
        self.reserved_for.is_some()
    }
}

/// Manual `Debug` that **redacts the blinding factor**. Deriving `Debug` would
/// print the secret blinding in logs/test output; this impl keeps it out.
impl std::fmt::Debug for StoredOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredOutput")
            .field("commitment", &self.commitment)
            .field("value", &self.value)
            .field("blinding", &"<redacted>")
            .field("origin", &self.origin)
            .field("status", &self.status)
            .field("origin_block", &self.origin_block)
            .field("is_coinbase", &self.is_coinbase)
            .field("derivable", &self.derivable)
            .field("reserved_for", &self.reserved_for)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}
