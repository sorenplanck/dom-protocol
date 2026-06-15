//! The output store (design §2.3 `outputs: Vec<StoredOutput>`).
//!
//! This sub-step (3A) implements the in-memory collection and its **read
//! surface** only — find by commitment, iterate, balance/count by status.
//! There is **no disk persistence** (3C) and **no reconciliation** (3B) here.
//!
//! The store deliberately exposes **no generic `remove`**: the only deletion is
//! [`OutputStore::remove_if_deletable`], gated by the `D1` guard
//! ([`StoredOutput::can_delete`]). This makes the retention invariant INV-RET a
//! structural property of the API, not merely a convention.

use crate::types::{OutputStatus, StoredOutput};
use thiserror::Error;

/// Errors from store mutations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    /// An output with this commitment is already present (commitment is the
    /// primary key).
    #[error("duplicate commitment")]
    DuplicateCommitment,
    /// No output with this commitment exists.
    #[error("output not found")]
    NotFound,
    /// Deletion refused: the output was canonical at some point and INV-RET
    /// forbids removing it (only an `Unconfirmed` output may be deleted, D1).
    #[error("output is not deletable (INV-RET): status is not Unconfirmed")]
    NotDeletable,
}

/// In-memory collection of [`StoredOutput`], keyed by commitment.
///
/// Backed by a `Vec` to mirror the persisted form of §2.3. Lookups are linear
/// for now; an index may be layered on in a later sub-step if profiling calls
/// for it.
#[derive(Debug, Default, Clone)]
pub struct OutputStore {
    outputs: Vec<StoredOutput>,
}

impl OutputStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild a store from a vector of records (e.g. loaded from disk).
    /// Inserts each through [`OutputStore::insert`], so a duplicate commitment
    /// in the persisted data is rejected with [`StoreError::DuplicateCommitment`]
    /// rather than silently admitted.
    pub fn from_outputs(outputs: Vec<StoredOutput>) -> Result<Self, StoreError> {
        let mut store = Self::default();
        for output in outputs {
            store.insert(output)?;
        }
        Ok(store)
    }

    /// Number of stored outputs (all statuses).
    pub fn len(&self) -> usize {
        self.outputs.len()
    }

    /// Whether the store holds no outputs.
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Insert a new output. Errors if its commitment is already present
    /// (the commitment is the primary key).
    pub fn insert(&mut self, output: StoredOutput) -> Result<(), StoreError> {
        if self.get(&output.commitment).is_some() {
            return Err(StoreError::DuplicateCommitment);
        }
        self.outputs.push(output);
        Ok(())
    }

    /// Find an output by its commitment (primary-key lookup).
    pub fn get(&self, commitment: &[u8; 33]) -> Option<&StoredOutput> {
        self.outputs.iter().find(|o| &o.commitment == commitment)
    }

    /// Mutable lookup by commitment — the handle the reconciler (3B) will use to
    /// drive state transitions.
    pub fn get_mut(&mut self, commitment: &[u8; 33]) -> Option<&mut StoredOutput> {
        self.outputs
            .iter_mut()
            .find(|o| &o.commitment == commitment)
    }

    /// Iterate over all stored outputs.
    pub fn iter(&self) -> impl Iterator<Item = &StoredOutput> {
        self.outputs.iter()
    }

    /// Mutable iteration over all stored outputs — the handle the reconciler
    /// (3B) uses to drive status-only transitions across the whole store.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut StoredOutput> {
        self.outputs.iter_mut()
    }

    /// Sum of values of outputs in the given status.
    pub fn balance(&self, status: OutputStatus) -> u64 {
        self.outputs
            .iter()
            .filter(|o| o.status == status)
            .map(|o| o.value)
            .sum()
    }

    /// Count of outputs in the given status.
    pub fn count(&self, status: OutputStatus) -> usize {
        self.outputs.iter().filter(|o| o.status == status).count()
    }

    /// Remove an output **only if** the `D1` guard allows it (still
    /// `Unconfirmed`). Returns the removed record. Any canonical output
    /// (`Confirmed`/`Spent`/`Reorged`) is refused with [`StoreError::NotDeletable`]
    /// — the store-level enforcement of INV-RET.
    ///
    /// Note: 3B will additionally require the producing slate to be terminally
    /// `Canceled`/`Failed` before calling this; that condition lives with the
    /// pending-slate layer, not here.
    pub fn remove_if_deletable(
        &mut self,
        commitment: &[u8; 33],
    ) -> Result<StoredOutput, StoreError> {
        let idx = self
            .outputs
            .iter()
            .position(|o| &o.commitment == commitment)
            .ok_or(StoreError::NotFound)?;
        if !self.outputs[idx].can_delete() {
            return Err(StoreError::NotDeletable);
        }
        Ok(self.outputs.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockRef, OutputOrigin, StoredOutput};

    fn out(tag: u8, value: u64, origin: OutputOrigin) -> StoredOutput {
        let mut commitment = [0u8; 33];
        commitment[0] = tag;
        StoredOutput::new_unconfirmed(commitment, value, [tag; 32], origin, false, None, 1000)
    }

    #[test]
    fn insert_and_get_by_commitment() {
        let mut s = OutputStore::new();
        let o = out(1, 100, OutputOrigin::Change);
        let key = o.commitment;
        s.insert(o).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(&key).unwrap().value, 100);
    }

    #[test]
    fn duplicate_commitment_rejected() {
        let mut s = OutputStore::new();
        s.insert(out(1, 100, OutputOrigin::Change)).unwrap();
        assert_eq!(
            s.insert(out(1, 200, OutputOrigin::Change)).unwrap_err(),
            StoreError::DuplicateCommitment
        );
    }

    #[test]
    fn balance_and_count_by_status() {
        let mut s = OutputStore::new();
        s.insert(out(1, 100, OutputOrigin::Change)).unwrap();
        s.insert(out(2, 250, OutputOrigin::ReceiveSlate)).unwrap();
        // Confirm the second one at block 5.
        let key2 = out(2, 0, OutputOrigin::Change).commitment;
        s.get_mut(&key2)
            .unwrap()
            .confirm(
                BlockRef {
                    height: 5,
                    hash: [5u8; 32],
                },
                1001,
            )
            .unwrap();

        assert_eq!(s.balance(OutputStatus::Unconfirmed), 100);
        assert_eq!(s.balance(OutputStatus::Confirmed), 250);
        assert_eq!(s.count(OutputStatus::Unconfirmed), 1);
        assert_eq!(s.count(OutputStatus::Confirmed), 1);
    }

    #[test]
    fn remove_if_deletable_allows_unconfirmed() {
        let mut s = OutputStore::new();
        let o = out(1, 100, OutputOrigin::Change);
        let key = o.commitment;
        s.insert(o).unwrap();
        let removed = s.remove_if_deletable(&key).unwrap();
        assert_eq!(removed.value, 100);
        assert!(s.is_empty());
    }

    #[test]
    fn remove_if_deletable_refuses_confirmed_inv_ret() {
        let mut s = OutputStore::new();
        let o = out(1, 100, OutputOrigin::Change);
        let key = o.commitment;
        s.insert(o).unwrap();
        s.get_mut(&key)
            .unwrap()
            .confirm(
                BlockRef {
                    height: 2,
                    hash: [2u8; 32],
                },
                1001,
            )
            .unwrap();
        // Confirmed (canonical) output cannot be removed — INV-RET.
        assert_eq!(
            s.remove_if_deletable(&key).unwrap_err(),
            StoreError::NotDeletable
        );
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn remove_missing_is_not_found() {
        let mut s = OutputStore::new();
        assert_eq!(
            s.remove_if_deletable(&[9u8; 33]).unwrap_err(),
            StoreError::NotFound
        );
    }
}
