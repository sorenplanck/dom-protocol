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

use crate::types::{OutputStatus, PayoutForV1, PayoutPinDisposition, PayoutPinError, StoredOutput};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Serialize the store transparently as its `Vec<StoredOutput>` (so the
/// persisted form matches design §2.3 `outputs: Vec<StoredOutput>`).
impl Serialize for OutputStore {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.outputs.serialize(s)
    }
}

/// Deserialize via [`OutputStore::from_outputs`], so the primary-key invariant
/// (no duplicate commitments) is enforced on load rather than silently admitted.
impl<'de> Deserialize<'de> for OutputStore {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let outputs = Vec::<StoredOutput>::deserialize(d)?;
        OutputStore::from_outputs(outputs).map_err(serde::de::Error::custom)
    }
}

/// Errors from store mutations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    /// An output with this commitment is already present (commitment is the
    /// primary key).
    #[error("duplicate commitment")]
    DuplicateCommitment,
    /// Two different outputs carried the same payout preparation digest.
    #[error("duplicate payout preparation digest")]
    DuplicatePayoutPin,
    /// One commitment was bound to two different payout preparations.
    #[error("conflicting payout preparation for output")]
    PayoutPinConflict,
    /// A backup tried to attach a payout pin to different immutable output
    /// material under an existing commitment.
    #[error("payout-pinned backup output identity mismatch")]
    PayoutOutputIdentityMismatch,
    /// No output with this commitment exists.
    #[error("output not found")]
    NotFound,
    /// Deletion refused: the output is canonical or carries an immutable payout
    /// pin. D1 permits only unpinned `Unconfirmed` outputs.
    #[error("output is not deletable (INV-RET or payout pin)")]
    NotDeletable,
}

/// Summary of a non-destructive backup merge ([`OutputStore::merge_backup`]).
/// `inserted + advanced + kept` equals the number of incoming records; no
/// existing record is ever removed or downgraded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Incoming outputs that were absent locally and got inserted.
    pub inserted: usize,
    /// Existing outputs whose status was advanced to the backup's (strictly
    /// more advanced).
    pub advanced: usize,
    /// Existing outputs left unchanged (backup not more advanced).
    pub kept: usize,
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
        if let Some(pin) = output.payout_for() {
            if self
                .outputs
                .iter()
                .any(|existing| existing.payout_for() == Some(pin))
            {
                return Err(StoreError::DuplicatePayoutPin);
            }
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

    /// Bind one existing output to an authority-minted payout preparation.
    ///
    /// The preparation digest is globally unique within this wallet. An exact
    /// retry on the same output is idempotent; reuse on any other output or a
    /// different pin on this output fails without mutation.
    pub fn pin_payout(
        &mut self,
        commitment: &[u8; 33],
        payout_for: PayoutForV1,
        now: u64,
    ) -> Result<PayoutPinDisposition, StoreError> {
        if self.outputs.iter().any(|output| {
            &output.commitment != commitment && output.payout_for() == Some(payout_for)
        }) {
            return Err(StoreError::DuplicatePayoutPin);
        }
        self.get_mut(commitment)
            .ok_or(StoreError::NotFound)?
            .pin_payout(payout_for, now)
            .map_err(|error| match error {
                PayoutPinError::Conflict => StoreError::PayoutPinConflict,
                PayoutPinError::ZeroPrepareDigest => StoreError::DuplicatePayoutPin,
            })
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

    /// Non-destructive merge of outputs from an encrypted backup (design §2.7).
    ///
    /// For each incoming record:
    /// - **absent** → inserted (recovers a lost, typically non-derivable output);
    /// - **present** → keep the status of higher [`OutputStatus::merge_rank`].
    ///   The backup's status is adopted **only if strictly more advanced**;
    ///   otherwise the current one is kept. The record is never removed and the
    ///   status is never downgraded — INV-RET. When advancing, the backup's
    ///   `origin_block` is taken if present and `updated_at` is moved forward.
    ///
    /// The blinding is identical per commitment (same output), so it is never
    /// touched. The caller SHOULD run [`crate::reconcile`] afterwards to bring
    /// statuses up to the current tip (§2.7) — the merge itself only guarantees
    /// no loss and no downgrade, not chain-consistency.
    pub fn merge_backup(&mut self, incoming: Vec<StoredOutput>) -> Result<MergeReport, StoreError> {
        // Rebuild the incoming set first so duplicate commitments or payout
        // pins fail before any local state can change. Apply the merge to a
        // clone for the same reason: a conflict in a later record must not
        // leave an earlier record partially imported.
        let incoming = OutputStore::from_outputs(incoming)?.outputs;
        let mut candidate = self.clone();
        let mut report = MergeReport::default();
        for out_bak in incoming {
            match candidate.get(&out_bak.commitment) {
                None => {
                    candidate.insert(out_bak)?;
                    report.inserted += 1;
                }
                Some(existing) => {
                    if let Some(incoming_pin) = out_bak.payout_for() {
                        if candidate.outputs.iter().any(|output| {
                            output.commitment != out_bak.commitment
                                && output.payout_for() == Some(incoming_pin)
                        }) {
                            return Err(StoreError::DuplicatePayoutPin);
                        }
                    }
                    match (existing.payout_for(), out_bak.payout_for()) {
                        (Some(local), Some(incoming)) if local != incoming => {
                            return Err(StoreError::PayoutPinConflict)
                        }
                        (_, Some(_)) if !same_payout_output_identity(existing, &out_bak) => {
                            return Err(StoreError::PayoutOutputIdentityMismatch)
                        }
                        _ => {}
                    }
                    let existing_rank = existing.status.merge_rank();
                    let incoming_pin = out_bak.payout_for();
                    let incoming_updated_at = out_bak.updated_at;
                    if out_bak.status.merge_rank() > existing_rank {
                        let slot = candidate
                            .get_mut(&out_bak.commitment)
                            .expect("commitment present");
                        slot.status = out_bak.status;
                        if out_bak.origin_block.is_some() {
                            slot.origin_block = out_bak.origin_block;
                        }
                        slot.updated_at = slot.updated_at.max(out_bak.updated_at);
                        report.advanced += 1;
                    } else {
                        report.kept += 1;
                    }
                    if let Some(pin) = incoming_pin {
                        let slot = candidate
                            .get_mut(&out_bak.commitment)
                            .expect("commitment present");
                        let pin_updated_at = slot.updated_at.max(incoming_updated_at);
                        match slot.pin_payout(pin, pin_updated_at) {
                            Ok(_) => {}
                            Err(PayoutPinError::Conflict) => {
                                return Err(StoreError::PayoutPinConflict)
                            }
                            Err(PayoutPinError::ZeroPrepareDigest) => {
                                return Err(StoreError::DuplicatePayoutPin)
                            }
                        }
                    }
                }
            }
        }
        *self = candidate;
        Ok(report)
    }

    /// Remove an output **only if** the `D1` guard allows it (still
    /// `Unconfirmed`). Returns the removed record. Any canonical output
    /// (`Confirmed`/`Spent`/`Reorged`) or an output with a durable payout pin is
    /// refused with [`StoreError::NotDeletable`] — the store-level enforcement
    /// of INV-RET and payout ownership.
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

fn same_payout_output_identity(local: &StoredOutput, incoming: &StoredOutput) -> bool {
    local.commitment == incoming.commitment
        && local.value == incoming.value
        && *local.blinding == *incoming.blinding
        && local.origin == incoming.origin
        && local.is_coinbase == incoming.is_coinbase
        && local.derivable == incoming.derivable
        && local.created_at == incoming.created_at
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockRef, OutputOrigin, PayoutForV1, StoredOutput};

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
    fn duplicate_payout_pin_rejected_across_outputs() {
        let pin = PayoutForV1::new([0x44; 32]).unwrap();
        let mut first = out(1, 100, OutputOrigin::ReceiveSlate);
        first.pin_payout(pin, 1001).unwrap();
        let mut second = out(2, 200, OutputOrigin::ReceiveSlate);
        second.pin_payout(pin, 1001).unwrap();
        let mut store = OutputStore::new();
        store.insert(first).unwrap();
        assert_eq!(
            store.insert(second).unwrap_err(),
            StoreError::DuplicatePayoutPin
        );
    }

    #[test]
    fn store_payout_pin_api_is_global_one_shot_and_read_only_on_conflict() {
        let mut store = OutputStore::new();
        let first = out(1, 100, OutputOrigin::ReceiveSlate);
        let first_key = first.commitment;
        let second = out(2, 200, OutputOrigin::ReceiveSlate);
        let second_key = second.commitment;
        store.insert(first).unwrap();
        store.insert(second).unwrap();
        let pin = PayoutForV1::new([0x45; 32]).unwrap();
        assert_eq!(
            store.pin_payout(&first_key, pin, 1001).unwrap(),
            PayoutPinDisposition::Pinned
        );
        assert_eq!(
            store.pin_payout(&first_key, pin, 1002).unwrap(),
            PayoutPinDisposition::Idempotent
        );
        assert_eq!(
            store.pin_payout(&second_key, pin, 1003).unwrap_err(),
            StoreError::DuplicatePayoutPin
        );
        assert!(store.get(&second_key).unwrap().payout_for().is_none());
    }

    #[test]
    fn merge_payout_conflict_is_atomic_even_after_an_earlier_insert() {
        let mut local = out(1, 100, OutputOrigin::ReceiveSlate);
        local
            .pin_payout(PayoutForV1::new([0x11; 32]).unwrap(), 1001)
            .unwrap();
        let mut store = OutputStore::new();
        store.insert(local).unwrap();

        let earlier = out(2, 200, OutputOrigin::Change);
        let mut conflict = out(1, 100, OutputOrigin::ReceiveSlate);
        conflict
            .pin_payout(PayoutForV1::new([0x22; 32]).unwrap(), 1002)
            .unwrap();
        assert_eq!(
            store.merge_backup(vec![earlier, conflict]).unwrap_err(),
            StoreError::PayoutPinConflict
        );
        assert_eq!(store.len(), 1);
        let key_one = out(1, 0, OutputOrigin::Change).commitment;
        let key_two = out(2, 0, OutputOrigin::Change).commitment;
        assert!(store.get(&key_two).is_none());
        assert_eq!(
            store.get(&key_one).unwrap().payout_for(),
            Some(PayoutForV1::new([0x11; 32]).unwrap())
        );
    }

    #[test]
    fn merge_adopts_exact_pin_but_preserves_a_newer_local_pin() {
        let mut store = OutputStore::new();
        store
            .insert(out(1, 100, OutputOrigin::ReceiveSlate))
            .unwrap();
        let pin = PayoutForV1::new([0x33; 32]).unwrap();
        let mut incoming = out(1, 100, OutputOrigin::ReceiveSlate);
        incoming.pin_payout(pin, 1001).unwrap();
        store.merge_backup(vec![incoming]).unwrap();
        let key = out(1, 0, OutputOrigin::Change).commitment;
        assert_eq!(store.get(&key).unwrap().payout_for(), Some(pin));

        let stale = out(1, 100, OutputOrigin::ReceiveSlate);
        store.merge_backup(vec![stale]).unwrap();
        assert_eq!(store.get(&key).unwrap().payout_for(), Some(pin));
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
    fn remove_if_deletable_refuses_unconfirmed_payout_pin() {
        let mut output = out(1, 100, OutputOrigin::ReceiveSlate);
        output
            .pin_payout(PayoutForV1::new([0x55; 32]).unwrap(), 1001)
            .unwrap();
        let mut store = OutputStore::new();
        store.insert(output).unwrap();
        let key = out(1, 0, OutputOrigin::Change).commitment;
        assert_eq!(
            store.remove_if_deletable(&key).unwrap_err(),
            StoreError::NotDeletable
        );
        assert_eq!(store.len(), 1);
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
