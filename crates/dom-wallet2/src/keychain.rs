//! Keychain derivation engine (design §7.4) — the bridge from "my seed" to "my
//! derivable outputs".
//!
//! Derives the wallet-owned blindings from the [`KeychainV2`] seed using the
//! shared [`dom_wallet_keys`] crate (#76), so coinbase/receive blindings are
//! **byte-identical to v1** — a divergent derivation would produce different
//! commitments and the wallet would not recognize its own outputs.
//!
//! ## The derivable / non-derivable boundary (the essence of v2)
//! Only two output kinds are seed-derivable:
//! - **coinbase** — by block height (`m/44'/330'/0'/1'/height'`);
//! - **receive-request** — by index (`m/44'/330'/account'/0/index`).
//!
//! **change** and **receive-slate** have RANDOM blindings: they exist nowhere
//! but the store and are recovered only via the store backup (the 2nd layer,
//! §2.7). [`restore_coinbase_from_seed`] therefore reconstructs **only** the
//! derivable coinbase set; it does not — and cannot — touch the non-derivable
//! ones. `StoredOutput.derivable` is metadata for exactly this: it never gates
//! retention (that is what breaks v1).
//!
//! ## Deferred (tracked: RB-WALLET2-RECEIVE-RESTORE)
//! Restore-from-seed of **receive-requests** is not implemented here. Matching a
//! receive-request needs its **amount** to compute the commitment, and the
//! amount is neither on-chain (hidden in the Pedersen commitment) nor derivable
//! from the seed — so it needs an amount source (the store/backup, i.e. the same
//! 2nd layer). See `docs/RELEASE_BLOCKERS.md`.

use crate::types::{BlockRef, DerivIndex, KeychainV2, OutputOrigin, StoredOutput};
use dom_core::BlockHeight;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_wallet_keys::{coinbase_blinding, spend_output_blinding, ExtendedPrivKey, SeedError};
use thiserror::Error;

/// Errors from keychain derivation.
#[derive(Debug, Error)]
pub enum KeychainError {
    /// The keychain carries no seed; nothing can be derived.
    #[error("wallet has no seed; cannot derive keys")]
    NoSeed,
    /// Seed / HD derivation failed.
    #[error("seed derivation failed: {0}")]
    Derivation(#[from] SeedError),
    /// A derived 32-byte value was not a valid blinding factor (scalar).
    #[error("invalid derived blinding: {0}")]
    Blinding(String),
}

/// A deterministic receive request descriptor produced by
/// [`KeychainV2::create_receive_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveRequest {
    /// Compressed Pedersen commitment the sender should pay to.
    pub commitment: [u8; 33],
    /// The fixed amount of the request.
    pub amount: u64,
    /// The derivation index used (also persisted via the cursor).
    pub index: u32,
}

/// Derives wallet-owned blindings from the keychain seed. The HD root is derived
/// once on construction and reused.
pub struct KeychainDeriver {
    root: ExtendedPrivKey,
    account: u32,
}

impl KeychainDeriver {
    /// Build a deriver from the keychain's seed. Errors with
    /// [`KeychainError::NoSeed`] if the keychain has no seed.
    pub fn new(keychain: &KeychainV2) -> Result<Self, KeychainError> {
        let seed = keychain.seed_bytes.as_ref().ok_or(KeychainError::NoSeed)?;
        let root = ExtendedPrivKey::from_seed(&seed[..])
            .map_err(|e| KeychainError::Derivation(e.into()))?;
        Ok(Self {
            root,
            account: keychain.account,
        })
    }

    /// Coinbase output blinding for `height` (`m/44'/330'/0'/1'/height'`).
    pub fn coinbase_blinding(&self, height: u64) -> Result<BlindingFactor, KeychainError> {
        let bytes = coinbase_blinding(&self.root, height)?;
        BlindingFactor::from_bytes(*bytes).map_err(|e| KeychainError::Blinding(e.to_string()))
    }

    /// Deterministic receive/spend output blinding for `index`
    /// (`m/44'/330'/account'/0/index`).
    pub fn receive_blinding(&self, index: u32) -> Result<BlindingFactor, KeychainError> {
        let bytes = spend_output_blinding(&self.root, self.account, index)?;
        BlindingFactor::from_bytes(*bytes).map_err(|e| KeychainError::Blinding(e.to_string()))
    }
}

impl KeychainV2 {
    /// Create a deterministic fixed-amount receive request: derive the blinding
    /// at the current `next_receive_index`, commit to `amount`, and **advance the
    /// cursor**. The blinding is recoverable from the seed by this index.
    pub fn create_receive_request(&mut self, amount: u64) -> Result<ReceiveRequest, KeychainError> {
        let deriver = KeychainDeriver::new(self)?;
        let index = self.next_receive_index;
        let blinding = deriver.receive_blinding(index)?;
        let commitment = *Commitment::commit(amount, &blinding).as_bytes();
        self.next_receive_index = self.next_receive_index.saturating_add(1);
        Ok(ReceiveRequest {
            commitment,
            amount,
            index,
        })
    }
}

/// One scanned block for restore-from-seed. Carries the output commitments AND
/// the block fee total, so the coinbase candidate value (`reward + fees`) can be
/// computed — a restore-specific input (richer than the reconciler's
/// [`crate::ScanBlock`]), deliberately a plain struct so restore is testable with
/// a fake and is NOT coupled to the node RPC.
#[derive(Debug, Clone, Default)]
pub struct RestoreBlock {
    /// Block height.
    pub height: u64,
    /// 32-byte block hash (recorded on the reconstructed output).
    pub hash: [u8; 32],
    /// Output commitments created in this block.
    pub output_commitments: Vec<[u8; 33]>,
    /// Commitments consumed as inputs in this block. Restore itself does not
    /// match inputs, but carrying them lets one `/chain/scan` walk feed BOTH
    /// restore and the reconciler ([`crate::reconcile::ScanBlock`] needs them
    /// for spend detection) instead of paying a second full-chain fetch.
    pub input_commitments: Vec<[u8; 33]>,
    /// Total transaction fees in this block (noms) — added to the reward for the
    /// coinbase candidate value.
    pub total_fees_noms: u64,
}

impl From<&RestoreBlock> for crate::reconcile::ScanBlock {
    /// Project a restore block into the reconciler's view block — same walk,
    /// two consumers. Drops only `total_fees_noms` (the reconciler does not
    /// need it).
    fn from(b: &RestoreBlock) -> Self {
        Self {
            height: b.height,
            hash: b.hash,
            output_commitments: b.output_commitments.clone(),
            input_commitments: b.input_commitments.clone(),
        }
    }
}

/// Reconstruct the **derivable coinbase** outputs from the seed by deriving the
/// per-height coinbase blinding and matching its commitment against the scan
/// (design §7.4). Returns the recovered outputs at `Confirmed{block}` (run
/// [`crate::reconcile`] afterwards to refine status — e.g. mark a spent coinbase
/// `Spent`).
///
/// **Boundary:** this recovers ONLY coinbase outputs. Change and receive-slate
/// (random blindings) cannot be matched — no key derives them — so they are not
/// recovered here and must come from the store backup (§2.7). See the module
/// docs for the receive-request restore follow-up.
pub fn restore_coinbase_from_seed(
    keychain: &KeychainV2,
    blocks: &[RestoreBlock],
    now: u64,
) -> Result<Vec<StoredOutput>, KeychainError> {
    let deriver = KeychainDeriver::new(keychain)?;
    let mut recovered = Vec::new();

    for block in blocks {
        let blinding = deriver.coinbase_blinding(block.height)?;
        let blinding_bytes = *blinding.as_bytes();
        let reward = dom_core::block_reward(BlockHeight(block.height)).noms();
        // Try the bare reward and reward+fees (a coinbase claims both).
        let candidates: [u64; 2] = [reward, reward.saturating_add(block.total_fees_noms)];

        for &commitment in &block.output_commitments {
            for &value in candidates.iter() {
                if value == 0 {
                    continue;
                }
                if Commitment::commit(value, &blinding).as_bytes() == &commitment {
                    let mut out = StoredOutput::new_unconfirmed(
                        commitment,
                        value,
                        blinding_bytes,
                        OutputOrigin::Coinbase,
                        true,
                        Some(DerivIndex::CoinbaseHeight(block.height)),
                        now,
                    );
                    out.confirm(
                        BlockRef {
                            height: block.height,
                            hash: block.hash,
                        },
                        now,
                    )
                    .expect("Unconfirmed -> Confirmed is T1, always legal");
                    recovered.push(out);
                    break; // first matching value wins for this commitment
                }
            }
        }
    }

    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Network, OutputStatus};
    use dom_wallet_keys::{Bip39Seed, SeedAcceptance};
    use zeroize::Zeroizing;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon art";

    fn keychain_with_seed() -> KeychainV2 {
        let seed = Bip39Seed::from_phrase(PHRASE, SeedAcceptance::NewWallet).unwrap();
        KeychainV2 {
            seed_bytes: Some(Zeroizing::new(*seed.seed_bytes())),
            seed_word_count: Some(24),
            account: 0,
            ..Default::default()
        }
    }

    #[test]
    fn no_seed_cannot_derive() {
        let k = KeychainV2::default();
        assert!(matches!(
            KeychainDeriver::new(&k),
            Err(KeychainError::NoSeed)
        ));
    }

    #[test]
    fn coinbase_blinding_matches_shared_derivation() {
        // The deriver must reproduce dom-wallet-keys exactly (byte-identical).
        let k = keychain_with_seed();
        let deriver = KeychainDeriver::new(&k).unwrap();
        let root = ExtendedPrivKey::from_seed(&k.seed_bytes.as_ref().unwrap()[..]).unwrap();
        let expected = coinbase_blinding(&root, 7).unwrap();
        assert_eq!(deriver.coinbase_blinding(7).unwrap().as_bytes(), &*expected);
    }

    #[test]
    fn create_receive_request_advances_cursor_and_is_deterministic() {
        let mut k = keychain_with_seed();
        assert_eq!(k.next_receive_index, 0);
        let r0 = k.create_receive_request(1000).unwrap();
        assert_eq!(r0.index, 0);
        assert_eq!(r0.amount, 1000);
        assert_eq!(k.next_receive_index, 1);
        let r1 = k.create_receive_request(1000).unwrap();
        assert_eq!(r1.index, 1);
        assert_ne!(
            r0.commitment, r1.commitment,
            "different index → different output"
        );

        // Deterministic: a fresh keychain at index 0 reproduces r0's commitment.
        let mut k2 = keychain_with_seed();
        let again = k2.create_receive_request(1000).unwrap();
        assert_eq!(again.commitment, r0.commitment);
    }

    /// V-11 — restore recovers ONLY derivable outputs. A coinbase (seed-derivable
    /// by height) is recovered; a non-derivable output (random blinding, like a
    /// receive-slate or change) sitting in the same block is NOT — it has no key
    /// the seed can derive, so it can only come from the store/backup.
    #[test]
    fn restore_from_seed_recovers_only_derivable() {
        let k = keychain_with_seed();
        let deriver = KeychainDeriver::new(&k).unwrap();

        // The real coinbase commitment at height 1 (value = reward, no fees).
        let height = 1u64;
        let reward = dom_core::block_reward(BlockHeight(height)).noms();
        assert!(reward > 0);
        let cb_blinding = deriver.coinbase_blinding(height).unwrap();
        let coinbase_commitment = *Commitment::commit(reward, &cb_blinding).as_bytes();

        // A NON-derivable output: random blinding (the change / receive-slate case).
        let random_blinding = BlindingFactor::from_bytes([0x9au8; 32]).unwrap();
        let non_derivable_commitment = *Commitment::commit(500, &random_blinding).as_bytes();

        let blocks = vec![RestoreBlock {
            height,
            hash: [1u8; 32],
            output_commitments: vec![coinbase_commitment, non_derivable_commitment],
            input_commitments: vec![],
            total_fees_noms: 0,
        }];

        let recovered = restore_coinbase_from_seed(&k, &blocks, 1000).unwrap();

        // Exactly the coinbase is recovered.
        assert_eq!(
            recovered.len(),
            1,
            "only the derivable coinbase is recovered"
        );
        let cb = &recovered[0];
        assert_eq!(cb.commitment, coinbase_commitment);
        assert_eq!(cb.value, reward);
        assert_eq!(cb.origin, OutputOrigin::Coinbase);
        assert_eq!(cb.status, OutputStatus::Confirmed);
        assert_eq!(cb.derivable, Some(DerivIndex::CoinbaseHeight(height)));
        assert!(cb.is_coinbase);
        assert_eq!(*cb.blinding, *cb_blinding.as_bytes());

        // The non-derivable output is NOT recovered — it needs the store/backup.
        assert!(
            !recovered
                .iter()
                .any(|o| o.commitment == non_derivable_commitment),
            "non-derivable output must NOT be recovered from the seed"
        );
    }

    #[test]
    fn restore_matches_reward_plus_fees() {
        let k = keychain_with_seed();
        let deriver = KeychainDeriver::new(&k).unwrap();
        let height = 2u64;
        let fees = 137u64;
        let reward = dom_core::block_reward(BlockHeight(height)).noms();
        let cb_blinding = deriver.coinbase_blinding(height).unwrap();
        // Coinbase claims reward + fees.
        let commitment = *Commitment::commit(reward + fees, &cb_blinding).as_bytes();

        let blocks = vec![RestoreBlock {
            height,
            hash: [2u8; 32],
            output_commitments: vec![commitment],
            input_commitments: vec![],
            total_fees_noms: fees,
        }];
        let recovered = restore_coinbase_from_seed(&k, &blocks, 1000).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].value, reward + fees);
    }

    #[test]
    fn restore_with_no_seed_errors() {
        let k = KeychainV2::default(); // no seed
        let err = restore_coinbase_from_seed(&k, &[], 1000).unwrap_err();
        assert!(matches!(err, KeychainError::NoSeed));
        // sanity: a network/chain_id wrapper is unrelated to the seed error.
        let _ = Network::Regtest;
    }
}
