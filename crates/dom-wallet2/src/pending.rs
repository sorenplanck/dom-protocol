//! In-flight interactive slates (design §2.5) — the data model only.
//!
//! An interactive slate (sender ⇄ receiver ⇄ sender) is **not atomic**: the
//! wallet must persist the in-flight state between steps. [`PendingSlate`] holds
//! that state, keyed by `slate_hash`. The secret material it carries
//! ([`SlateSecrets`]) is protected with the same rigor as the seed and the output
//! blindings: wrapped in [`Zeroizing`] (wiped on drop), redacted from `Debug`, and
//! persisted **only inside the encrypted `WalletV2State`** — never in `slate_bytes`
//! (public), never in a journal or exported slate.
//!
//! This sub-step (7A) is the secure data model only. The orchestration that
//! produces these (create_send / receive / finalize / cancel, consuming
//! `dom-slate`) is sub-step 7B.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Which side of the interactive protocol this slate is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlateRole {
    /// We initiated the send (we own the change output).
    Sender,
    /// We are receiving (we own the recipient output).
    Receiver,
}

/// Lifecycle of an in-flight slate (design §2.5 / §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlateLifecycle {
    /// Built locally, not yet exchanged/broadcast.
    Built,
    /// The finalized tx was submitted to the network.
    Submitted,
    /// The slate was finalized into a complete transaction.
    Finalized,
    /// The produced output was confirmed on-chain.
    Confirmed,
    /// The slate failed (validation, expiry, …) and will not complete.
    Failed,
    /// The slate was explicitly canceled.
    Canceled,
}

impl SlateLifecycle {
    /// Whether this is a terminal-failure state. A `D1` deletion of the produced
    /// `Unconfirmed` output is permitted only when the slate is terminally
    /// `Failed`/`Canceled` (checked by the cancel path in 7B).
    pub fn is_terminal_failure(self) -> bool {
        matches!(self, SlateLifecycle::Failed | SlateLifecycle::Canceled)
    }
}

/// The secret material of an in-flight slate, by role. All fields are
/// [`Zeroizing`] (wiped on drop) and serialized with the same 32-byte codec as
/// the output blindings; they live only inside the encrypted payload.
#[derive(Clone, Serialize, Deserialize)]
pub enum SlateSecrets {
    /// Sender's excess blinding `x_S` and single-use nonce `k_S` (the nonce is
    /// discarded after `finalize`).
    Sender {
        /// Sender excess blinding.
        #[serde(with = "crate::types::serde_blinding")]
        excess_blinding: Zeroizing<[u8; 32]>,
        /// Sender single-use nonce.
        #[serde(with = "crate::types::serde_blinding")]
        nonce: Zeroizing<[u8; 32]>,
    },
    /// Receiver's random output blinding `x_R` (non-derivable — the WDSF case).
    Receiver {
        /// Recipient output blinding.
        #[serde(with = "crate::types::serde_blinding")]
        output_blinding: Zeroizing<[u8; 32]>,
    },
}

/// Manual `Debug` that **redacts every secret**. Deriving `Debug` would print the
/// blindings/nonce; this keeps them out of logs and test output.
impl std::fmt::Debug for SlateSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlateSecrets::Sender { .. } => f
                .debug_struct("SlateSecrets::Sender")
                .field("excess_blinding", &"<redacted>")
                .field("nonce", &"<redacted>")
                .finish(),
            SlateSecrets::Receiver { .. } => f
                .debug_struct("SlateSecrets::Receiver")
                .field("output_blinding", &"<redacted>")
                .finish(),
        }
    }
}

/// Custom serde for `Vec<[u8; 33]>` (serde has no array impl beyond length 32).
mod serde_commitments {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(v: &[[u8; 33]], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_vecs: Vec<&[u8]> = v.iter().map(|c| &c[..]).collect();
        as_vecs.serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<[u8; 33]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: Vec<Vec<u8>> = Vec::deserialize(d)?;
        raw.into_iter()
            .map(|b| {
                if b.len() != 33 {
                    return Err(serde::de::Error::custom("commitment must be 33 bytes"));
                }
                let mut a = [0u8; 33];
                a.copy_from_slice(&b);
                Ok(a)
            })
            .collect()
    }
}

/// Custom serde for `Option<[u8; 33]>`.
mod serde_commitment_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &Option<[u8; 33]>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match v {
            Some(c) => s.serialize_some(&c[..]),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<[u8; 33]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(b) => {
                if b.len() != 33 {
                    return Err(serde::de::Error::custom("commitment must be 33 bytes"));
                }
                let mut a = [0u8; 33];
                a.copy_from_slice(&b);
                Ok(Some(a))
            }
        }
    }
}

/// One in-flight interactive slate (design §2.5).
///
/// `Debug` is derived: the only secret-bearing field is [`SlateSecrets`], which
/// redacts itself. `slate_bytes` is public wire data; `reserved_inputs` /
/// `produced_output` are commitments (not secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSlate {
    /// `blake2b_256(slate_bytes)` of this phase — the key.
    pub slate_hash: [u8; 32],
    /// Which side we are.
    pub role: SlateRole,
    /// The PUBLIC slate wire bytes (no secrets).
    pub slate_bytes: Vec<u8>,
    /// Encrypted-at-rest secret material; redacted from `Debug`. `None` once the
    /// secrets are no longer needed (wiped at `finalize`, when the `Zeroizing`
    /// drop clears the memory) — the single-use nonce is discarded.
    #[serde(default)]
    pub secrets: Option<SlateSecrets>,
    /// For a sender: the input commitments reserved by this slate.
    #[serde(with = "serde_commitments", default)]
    pub reserved_inputs: Vec<[u8; 33]>,
    /// Commitment of the local `StoredOutput` this slate creates (change for a
    /// sender, recipient output for a receiver) — the link that lets a terminal
    /// `Failed`/`Canceled` slate `D1`-delete its still-`Unconfirmed` output.
    #[serde(with = "serde_commitment_opt", default)]
    pub produced_output: Option<[u8; 33]>,
    /// Lifecycle state.
    pub status: SlateLifecycle,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_slate_secrets() {
        let s = SlateSecrets::Sender {
            excess_blinding: Zeroizing::new([0x11u8; 32]),
            nonce: Zeroizing::new([0x22u8; 32]),
        };
        let dump = format!("{s:?}");
        assert!(dump.contains("<redacted>"));
        assert!(
            !dump.contains("11, 11, 11"),
            "excess_blinding leaked via Debug"
        );
        assert!(!dump.contains("22, 22, 22"), "nonce leaked via Debug");

        let r = SlateSecrets::Receiver {
            output_blinding: Zeroizing::new([0x33u8; 32]),
        };
        let dump = format!("{r:?}");
        assert!(dump.contains("<redacted>"));
        assert!(
            !dump.contains("33, 33, 33"),
            "output_blinding leaked via Debug"
        );
    }

    #[test]
    fn terminal_failure_classification() {
        assert!(SlateLifecycle::Failed.is_terminal_failure());
        assert!(SlateLifecycle::Canceled.is_terminal_failure());
        for s in [
            SlateLifecycle::Built,
            SlateLifecycle::Submitted,
            SlateLifecycle::Finalized,
            SlateLifecycle::Confirmed,
        ] {
            assert!(!s.is_terminal_failure());
        }
    }
}
