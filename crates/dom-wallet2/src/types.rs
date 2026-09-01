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
use thiserror::Error;
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
// `pub(crate)` so the slate-secret fields (`pending.rs`) reuse the same codec.
pub(crate) mod serde_blinding {
    use serde::{Deserialize, Deserializer, Serializer};
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
        let bytes = Zeroizing::new(Vec::<u8>::deserialize(deserializer)?);
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("blinding factor must be 32 bytes"));
        }
        let mut array = Zeroizing::new([0u8; 32]);
        array.copy_from_slice(&bytes);
        Ok(array)
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

/// Durable, one-shot binding between an owned output and a prepared payout
/// record held by the production actuator store.
///
/// The digest is minted by that store from its authenticated preparation
/// record.  Wallet code may persist it once, or accept the exact same value on
/// recovery, but it never clears or replaces it.  Keeping this marker separate
/// from `reserved_for` is essential: `reserved_for` protects ordinary wallet
/// inputs, while this marker prevents one payout output from being promised to
/// two route sessions.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PayoutForSerdeV1")]
pub struct PayoutForV1 {
    prepare_digest: [u8; 32],
}

#[derive(Deserialize)]
struct PayoutForSerdeV1 {
    prepare_digest: [u8; 32],
}

impl TryFrom<PayoutForSerdeV1> for PayoutForV1 {
    type Error = PayoutPinError;

    fn try_from(value: PayoutForSerdeV1) -> Result<Self, Self::Error> {
        Self::new(value.prepare_digest)
    }
}

impl PayoutForV1 {
    /// Construct a pin from a nonzero, authority-minted preparation digest.
    pub fn new(prepare_digest: [u8; 32]) -> Result<Self, PayoutPinError> {
        if prepare_digest == [0; 32] {
            return Err(PayoutPinError::ZeroPrepareDigest);
        }
        Ok(Self { prepare_digest })
    }

    /// Exact preparation digest persisted by the wallet.
    pub const fn prepare_digest(self) -> [u8; 32] {
        self.prepare_digest
    }
}

impl core::fmt::Debug for PayoutForV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PayoutForV1(<pinned>)")
    }
}

/// Errors from the immutable payout pin on one wallet output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PayoutPinError {
    /// Zero cannot identify an authenticated preparation record.
    #[error("payout preparation digest must be nonzero")]
    ZeroPrepareDigest,
    /// The output is already pinned to a different preparation record.
    #[error("output is already pinned to a different payout preparation")]
    Conflict,
}

/// Result of applying an exact payout pin to a wallet output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutPinDisposition {
    /// The output was unpinned and now durably needs persistence.
    Pinned,
    /// The same pin was already present; no wallet mutation occurred.
    Idempotent,
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
    /// Immutable payout preparation bound to this output, independent of input
    /// reservation and lifecycle status. Missing in legacy schema V2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payout_for: Option<PayoutForV1>,
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
        Self::new_unconfirmed_with_blinding(
            commitment,
            value,
            Zeroizing::new(blinding),
            origin,
            is_coinbase,
            derivable,
            now,
        )
    }

    /// Create an unconfirmed output by moving an already protected blinding
    /// owner into durable wallet state.  Slate/payment code uses this path so
    /// it never unwraps a `Zeroizing` transient into an unprotected array.
    pub(crate) fn new_unconfirmed_with_blinding(
        commitment: [u8; 33],
        value: u64,
        blinding: Zeroizing<[u8; 32]>,
        origin: OutputOrigin,
        is_coinbase: bool,
        derivable: Option<DerivIndex>,
        now: u64,
    ) -> Self {
        Self {
            commitment,
            value,
            blinding,
            origin,
            status: OutputStatus::Unconfirmed,
            origin_block: None,
            is_coinbase,
            derivable,
            reserved_for: None,
            payout_for: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Whether this output is currently reserved as a slate input.
    pub fn is_reserved(&self) -> bool {
        self.reserved_for.is_some()
    }

    /// The immutable payout preparation currently bound to this output.
    pub const fn payout_for(&self) -> Option<PayoutForV1> {
        self.payout_for
    }

    /// Pin this output exactly once for a prepared payout operation.
    ///
    /// An exact retry is idempotent. A different preparation is refused and
    /// leaves the output unchanged. There is deliberately no corresponding
    /// clear method: the historical binding survives confirmation, spending,
    /// reorg, backup and restore.
    pub(crate) fn pin_payout(
        &mut self,
        payout_for: PayoutForV1,
        now: u64,
    ) -> Result<PayoutPinDisposition, PayoutPinError> {
        match self.payout_for {
            None => {
                self.payout_for = Some(payout_for);
                self.updated_at = now;
                Ok(PayoutPinDisposition::Pinned)
            }
            Some(existing) if existing == payout_for => Ok(PayoutPinDisposition::Idempotent),
            Some(_) => Err(PayoutPinError::Conflict),
        }
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
            .field("payout_for", &self.payout_for.map(|_| "<pinned>"))
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Custom serde for the optional 64-byte BIP-39 seed (`Zeroizing<[u8; 64]>`).
///
/// `serde` only provides array impls up to length 32, so the 64-byte seed needs
/// an explicit codec. Mirrors v1's `serde_seed64_opt`. The seed is persisted
/// only inside the encrypted payload; this codec never runs against plaintext.
mod serde_seed64_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(seed: &Option<Zeroizing<[u8; 64]>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match seed {
            Some(bytes) => s.serialize_some(&bytes[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Zeroizing<[u8; 64]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<Vec<u8>>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(v) => {
                let v = Zeroizing::new(v);
                if v.len() != 64 {
                    return Err(serde::de::Error::custom("seed must be 64 bytes"));
                }
                let mut a = Zeroizing::new([0u8; 64]);
                a.copy_from_slice(&v);
                Ok(Some(a))
            }
        }
    }
}

/// Network identifier (wallet-side mirror of `dom_config::Network`, kept local so
/// the crate stays decoupled — same approach as v1's `dom-wallet/src/types.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Mainnet.
    Mainnet,
    /// Testnet.
    Testnet,
    /// Regtest — DEV-ONLY.
    Regtest,
}

impl Network {
    /// Coinbase maturity (blocks) for this network — mirrors v1's
    /// `Network::coinbase_maturity`. Mainnet / Testnet use the canonical
    /// `dom_core::COINBASE_MATURITY` (1000); Regtest uses
    /// `REGTEST_COINBASE_MATURITY` (1) so dev chains exercise spends quickly.
    pub fn coinbase_maturity(self) -> u64 {
        match self {
            Network::Mainnet | Network::Testnet => dom_core::COINBASE_MATURITY,
            Network::Regtest => dom_core::REGTEST_COINBASE_MATURITY,
        }
    }
}

/// Deterministic keychain state (design §2.6 `KeychainV2`, = v1
/// `WalletKeychainState`). This holds ONLY the persisted state — the seed and
/// the derivation cursors. The key-derivation logic (coinbase by height,
/// receive-request by index, restore-from-seed) is a separate sub-step.
///
/// The seed is persisted **encrypted** inside the wallet payload, never the
/// mnemonic phrase, and is wiped from memory on drop (`Zeroizing`).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct KeychainV2 {
    /// BIP-39 seed bytes (64) when this is a deterministic wallet.
    #[serde(
        default,
        with = "serde_seed64_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub seed_bytes: Option<Zeroizing<[u8; 64]>>,
    /// Original mnemonic word count. v2 wallets MUST be 24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_word_count: Option<u8>,
    /// Change-chain cursor for future deterministic change outputs.
    #[serde(default)]
    pub next_change_index: u32,
    /// Receive-chain cursor for future deterministic receive requests.
    #[serde(default)]
    pub next_receive_index: u32,
    /// BIP-44 account. v2 pins this to 0.
    #[serde(default)]
    pub account: u32,
}

/// Manual `Debug` that **redacts the seed**. Deriving `Debug` would print the
/// seed bytes (the master secret) in logs/test output; this impl keeps them out.
impl std::fmt::Debug for KeychainV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeychainV2")
            .field(
                "seed_bytes",
                &self.seed_bytes.as_ref().map(|_| "<redacted>"),
            )
            .field("seed_word_count", &self.seed_word_count)
            .field("next_change_index", &self.next_change_index)
            .field("next_receive_index", &self.next_receive_index)
            .field("account", &self.account)
            .finish()
    }
}

/// Store-level metadata (design §2.6 `StoreMeta`).
///
/// `last_reconciled_tip` / `last_reconciled_hash` record how far the store has
/// been reconciled — the cursors that unblock incremental sync (view B). The
/// `canonical_digest` (set drift detection) is deferred: it needs a hash
/// (blake2b) and the actual drift-detection wiring, which land later.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreMeta {
    /// Highest height already reconciled.
    #[serde(default)]
    pub last_reconciled_tip: u64,
    /// Hash of the block at `last_reconciled_tip`, when known.
    #[serde(default)]
    pub last_reconciled_hash: Option<[u8; 32]>,
}

#[cfg(test)]
mod payout_pin_tests {
    use super::*;

    fn output() -> StoredOutput {
        StoredOutput::new_unconfirmed(
            [2; 33],
            50,
            [3; 32],
            OutputOrigin::ReceiveSlate,
            false,
            None,
            10,
        )
    }

    #[test]
    fn payout_pin_is_one_shot_and_independent_from_input_reservation() {
        let mut output = output();
        output.reserved_for = Some([4; 32]);
        let first = PayoutForV1::new([5; 32]).unwrap();
        assert_eq!(
            output.pin_payout(first, 11).unwrap(),
            PayoutPinDisposition::Pinned
        );
        assert_eq!(output.reserved_for, Some([4; 32]));
        assert_eq!(output.payout_for(), Some(first));
        assert_eq!(
            output.pin_payout(first, 12).unwrap(),
            PayoutPinDisposition::Idempotent
        );
        assert_eq!(output.updated_at, 11, "exact retry must not mutate");
        assert_eq!(
            output
                .pin_payout(PayoutForV1::new([6; 32]).unwrap(), 13)
                .unwrap_err(),
            PayoutPinError::Conflict
        );
        assert_eq!(output.payout_for(), Some(first));
    }

    #[test]
    fn payout_pin_rejects_zero_and_redacts_debug() {
        assert_eq!(
            PayoutForV1::new([0; 32]).unwrap_err(),
            PayoutPinError::ZeroPrepareDigest
        );
        let mut output = output();
        output
            .pin_payout(PayoutForV1::new([0xAB; 32]).unwrap(), 11)
            .unwrap();
        let debug = format!("{output:?}");
        assert!(debug.contains("<pinned>"));
        assert!(!debug.contains("171, 171"));
        assert!(!debug.contains("ab, ab"));
    }
}
