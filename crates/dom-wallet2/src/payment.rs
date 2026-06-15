//! Sender-side payment orchestration (design §5.2 / §2.5) — slate → store.
//!
//! These are **pure state transitions** over [`WalletV2State`] (no disk I/O — the
//! caller persists via [`crate::save_wallet_state`]). The crypto is the shared,
//! pure [`dom_slate`]; this layer only does coin selection, the C0 inserts, the
//! input reservation and the cancel path.
//!
//! **Atomicity:** every action validates and calls `dom-slate` *before* it
//! mutates the state, so an early error (insufficient funds, slate failure)
//! leaves the state **untouched** — nothing is reserved or inserted.
//!
//! This sub-step (7B-i) covers the sender side + cancel. `receive` / `finalize`
//! (7B-ii) are not here.

use crate::pending::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
use crate::store::StoreError;
use crate::types::{OutputOrigin, OutputStatus, StoredOutput};
use crate::wallet_state::WalletV2State;
use dom_serialization::DomSerialize;
use dom_slate::{build_send, SlateError, SlateInput};
use dom_tx::slate::Slate;
use zeroize::Zeroizing;

/// Errors from the sender payment actions.
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    /// Not enough spendable balance to cover `amount + fee`. Nothing is reserved.
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds {
        /// Spendable total available.
        have: u64,
        /// `amount + fee` required.
        need: u64,
    },
    /// `amount + fee` overflowed `u64`.
    #[error("amount + fee overflow")]
    AmountOverflow,
    /// The slate crypto (`dom-slate`) failed.
    #[error("slate error: {0}")]
    Slate(#[from] SlateError),
    /// Slate serialization failed (for the slate hash).
    #[error("slate serialization: {0}")]
    Serialization(String),
    /// No pending slate with this hash.
    #[error("pending slate not found")]
    NotFound,
    /// A store invariant was violated (should not happen in normal flow).
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

/// Result of [`create_send`]: the public slate to hand to the recipient, and its
/// hash (the key under which the pending slate is tracked / canceled).
#[derive(Debug, Clone)]
pub struct SentSlate {
    /// Public step-1 slate to transmit to the recipient.
    pub slate: Slate,
    /// `blake2b_256(slate_bytes)` — the pending-slate key.
    pub slate_hash: [u8; 32],
}

/// Whether a stored output is spendable as an input now: `Confirmed`, not
/// reserved, and mature (coinbase respects the network's maturity vs `tip`).
fn is_spendable(out: &StoredOutput, tip: u64, maturity: u64) -> bool {
    if out.status != OutputStatus::Confirmed || out.is_reserved() {
        return false;
    }
    if out.is_coinbase {
        match out.origin_block {
            Some(b) => tip.saturating_sub(b.height) >= maturity,
            None => false,
        }
    } else {
        true
    }
}

/// Greedy coin selection (largest value first, commitment as a deterministic
/// tie-break) over the spendable set, accumulating until `need` is covered.
/// Returns the selected commitments and their sum, or `InsufficientFunds` with
/// the spendable total.
fn select_inputs(state: &WalletV2State, need: u64) -> Result<(Vec<[u8; 33]>, u64), PaymentError> {
    let tip = state.meta.last_reconciled_tip;
    let maturity = state.network.coinbase_maturity();

    let mut candidates: Vec<&StoredOutput> = state
        .outputs
        .iter()
        .filter(|o| is_spendable(o, tip, maturity))
        .collect();
    // Largest first → fewer inputs; commitment tie-break → deterministic.
    candidates.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.commitment.cmp(&b.commitment))
    });

    let total: u64 = candidates.iter().map(|o| o.value).sum();
    if total < need {
        return Err(PaymentError::InsufficientFunds { have: total, need });
    }

    let mut selected = Vec::new();
    let mut sum = 0u64;
    for o in candidates {
        if sum >= need {
            break;
        }
        selected.push(o.commitment);
        sum = sum.saturating_add(o.value);
    }
    Ok((selected, sum))
}

/// Build a send slate spending `amount` with `fee`, creating the change output
/// in the store at C0 and reserving the selected inputs (design §5.2, C0).
///
/// On success the state gains: a `StoredOutput{Change, Unconfirmed}` (using the
/// change material from `dom-slate` **verbatim**), a `PendingSlate{Sender}` with
/// the encrypted secrets, and `reserved_for` set on every selected input. On any
/// error (insufficient funds, slate failure) the state is unchanged.
pub fn create_send(
    state: &mut WalletV2State,
    amount: u64,
    fee: u64,
    now: u64,
) -> Result<SentSlate, PaymentError> {
    let need = amount
        .checked_add(fee)
        .ok_or(PaymentError::AmountOverflow)?;

    // 1) Select inputs (read-only) and assemble the slate inputs with blindings.
    let (selected, sum) = select_inputs(state, need)?;
    let inputs: Vec<SlateInput> = selected
        .iter()
        .map(|c| {
            let out = state.outputs.get(c).expect("selected output exists");
            SlateInput {
                commitment: *c,
                blinding: *out.blinding,
            }
        })
        .collect();
    let change_value = sum - need; // sum >= need guaranteed by select_inputs

    // 2) Slate crypto FIRST — this is the only fallible step before mutation.
    let sender = build_send(&inputs, change_value, amount, fee, state.chain_id)?;
    let slate_bytes = sender
        .slate
        .to_bytes()
        .map_err(|e| PaymentError::Serialization(e.to_string()))?;
    let slate_hash = *dom_crypto::blake2b_256(&slate_bytes).as_bytes();

    // 3) Mutate (all infallible from here): C0 change, pending slate, reservation.
    let produced_output = sender.change.as_ref().map(|c| c.commitment);
    if let Some(change) = &sender.change {
        // Use the change material VERBATIM — never recompute the commitment.
        state
            .outputs
            .insert(StoredOutput::new_unconfirmed(
                change.commitment,
                change.value,
                change.blinding,
                OutputOrigin::Change,
                false,
                None,
                now,
            ))
            .map_err(PaymentError::Store)?;
    }

    state.pending_slates.push(PendingSlate {
        slate_hash,
        role: SlateRole::Sender,
        slate_bytes,
        secrets: SlateSecrets::Sender {
            excess_blinding: Zeroizing::new(sender.excess_blinding),
            nonce: Zeroizing::new(sender.nonce),
        },
        reserved_inputs: selected.clone(),
        produced_output,
        status: SlateLifecycle::Built,
    });

    for c in &selected {
        if let Some(out) = state.outputs.get_mut(c) {
            out.reserve(slate_hash, now);
        }
    }

    Ok(SentSlate {
        slate: sender.slate,
        slate_hash,
    })
}

/// Cancel an in-flight slate (design §2.5 / §3 D1). Releases the reserved inputs
/// (the outputs are NOT deleted), `D1`-deletes the produced output **only if it
/// is still `Unconfirmed`** (if already `Confirmed` it is real money and is left
/// intact — INV-RET), and marks the slate `Canceled` (kept in the vec for
/// auditability; terminal-slate GC is a separate, explicit operation).
pub fn cancel(
    state: &mut WalletV2State,
    slate_hash: [u8; 32],
    now: u64,
) -> Result<(), PaymentError> {
    let idx = state
        .pending_slates
        .iter()
        .position(|p| p.slate_hash == slate_hash)
        .ok_or(PaymentError::NotFound)?;

    let reserved = state.pending_slates[idx].reserved_inputs.clone();
    let produced = state.pending_slates[idx].produced_output;

    // Release reservations — outputs stay, only `reserved_for` clears.
    for c in &reserved {
        if let Some(out) = state.outputs.get_mut(c) {
            out.release_reservation(now);
        }
    }

    // D1: delete the produced output ONLY while Unconfirmed; never a canonical one.
    if let Some(c) = produced {
        let deletable = state.outputs.get(&c).is_some_and(|o| o.can_delete());
        if deletable {
            let _ = state.outputs.remove_if_deletable(&c);
        }
    }

    state.pending_slates[idx].status = SlateLifecycle::Canceled;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BlockRef, Network};
    use dom_crypto::pedersen::{BlindingFactor, Commitment};

    /// A confirmed, mature, non-coinbase output with a real (commitment,blinding)
    /// pair, so `build_send` can do real crypto over it.
    fn funded_output(value: u64, now: u64) -> StoredOutput {
        let blinding = BlindingFactor::random();
        let commitment = *Commitment::commit(value, &blinding).as_bytes();
        let mut o = StoredOutput::new_unconfirmed(
            commitment,
            value,
            *blinding.as_bytes(),
            OutputOrigin::ReceiveSlate,
            false,
            None,
            now,
        );
        o.confirm(
            BlockRef {
                height: 10,
                hash: [10u8; 32],
            },
            now,
        )
        .unwrap();
        o
    }

    fn funded_state(values: &[u64]) -> WalletV2State {
        let mut state = WalletV2State::new(Network::Regtest, [0x77u8; 32]);
        state.meta.last_reconciled_tip = 100;
        for &v in values {
            state.outputs.insert(funded_output(v, 1000)).unwrap();
        }
        state
    }

    #[test]
    fn create_send_creates_change_c0_verbatim_and_reserves() {
        let mut state = funded_state(&[600, 600]);
        let before = state.outputs.len();

        let sent = create_send(&mut state, 1000, 10, 2000).unwrap();

        // A change output was created at C0 (Unconfirmed, Change).
        assert_eq!(state.outputs.len(), before + 1);
        let pending = &state.pending_slates[0];
        assert_eq!(pending.role, SlateRole::Sender);
        assert_eq!(pending.status, SlateLifecycle::Built);
        assert_eq!(pending.reserved_inputs.len(), 2);
        let change_c = pending.produced_output.expect("change exists");
        let change = state.outputs.get(&change_c).unwrap();
        assert_eq!(change.status, OutputStatus::Unconfirmed);
        assert_eq!(change.origin, OutputOrigin::Change);
        assert_eq!(change.value, 600 + 600 - 1010);

        // THE verbatim guarantee: the C0 change commitment is exactly the one
        // dom-slate put in the slate's change output.
        let slate_change = sent.slate.sender_change_output.as_ref().unwrap();
        assert_eq!(change.commitment, *slate_change.commitment.as_bytes());

        // Inputs are reserved under the slate hash.
        for c in &pending.reserved_inputs {
            assert_eq!(
                state.outputs.get(c).unwrap().reserved_for,
                Some(sent.slate_hash)
            );
        }
    }

    #[test]
    fn insufficient_funds_reserves_nothing() {
        let mut state = funded_state(&[500]);
        let snapshot_len = state.outputs.len();

        let err = create_send(&mut state, 1000, 10, 2000).unwrap_err();
        assert!(
            matches!(
                err,
                PaymentError::InsufficientFunds {
                    have: 500,
                    need: 1010
                }
            ),
            "got {err:?}"
        );
        // State untouched: no change, no pending, nothing reserved.
        assert_eq!(state.outputs.len(), snapshot_len);
        assert!(state.pending_slates.is_empty());
        assert!(state.outputs.iter().all(|o| !o.is_reserved()));
    }

    #[test]
    fn reservation_prevents_double_spend() {
        // Exactly enough for one send; the second must fail (inputs reserved).
        let mut state = funded_state(&[1100]);
        create_send(&mut state, 1000, 10, 2000).unwrap();
        let err = create_send(&mut state, 50, 10, 2001).unwrap_err();
        assert!(
            matches!(err, PaymentError::InsufficientFunds { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn immature_coinbase_is_not_spendable() {
        let mut state = WalletV2State::new(Network::Mainnet, [0x77u8; 32]);
        state.meta.last_reconciled_tip = 100; // maturity 1000 → height 10 immature
        let blinding = BlindingFactor::random();
        let commitment = *Commitment::commit(5000, &blinding).as_bytes();
        let mut cb = StoredOutput::new_unconfirmed(
            commitment,
            5000,
            *blinding.as_bytes(),
            OutputOrigin::Coinbase,
            true,
            None,
            1000,
        );
        cb.confirm(
            BlockRef {
                height: 10,
                hash: [10u8; 32],
            },
            1000,
        )
        .unwrap();
        state.outputs.insert(cb).unwrap();

        let err = create_send(&mut state, 1000, 10, 2000).unwrap_err();
        assert!(
            matches!(err, PaymentError::InsufficientFunds { have: 0, .. }),
            "immature coinbase must not be spendable; got {err:?}"
        );
    }

    #[test]
    fn cancel_releases_reservations_and_d1_deletes_unconfirmed_change() {
        let mut state = funded_state(&[600, 600]);
        let sent = create_send(&mut state, 1000, 10, 2000).unwrap();
        let change_c = state.pending_slates[0].produced_output.unwrap();
        assert!(state.outputs.get(&change_c).is_some());

        cancel(&mut state, sent.slate_hash, 3000).unwrap();

        // Reservations released; the produced Unconfirmed change is D1-deleted.
        assert!(state.outputs.iter().all(|o| !o.is_reserved()));
        assert!(
            state.outputs.get(&change_c).is_none(),
            "Unconfirmed change deleted"
        );
        // The pending slate is kept, marked Canceled (auditability).
        assert_eq!(state.pending_slates[0].status, SlateLifecycle::Canceled);
    }

    #[test]
    fn cancel_does_not_delete_confirmed_change_inv_ret() {
        // THE critical case: if the change already confirmed (tx mined before
        // cancel), cancel must NOT destroy it — it is real money.
        let mut state = funded_state(&[600, 600]);
        let sent = create_send(&mut state, 1000, 10, 2000).unwrap();
        let change_c = state.pending_slates[0].produced_output.unwrap();
        // Confirm the change on-chain.
        state
            .outputs
            .get_mut(&change_c)
            .unwrap()
            .confirm(
                BlockRef {
                    height: 12,
                    hash: [12u8; 32],
                },
                2500,
            )
            .unwrap();

        cancel(&mut state, sent.slate_hash, 3000).unwrap();

        // The Confirmed change is RETAINED (INV-RET) — cancel is a no-op on it.
        let change = state
            .outputs
            .get(&change_c)
            .expect("confirmed change retained");
        assert_eq!(change.status, OutputStatus::Confirmed);
        // Reservations still released; slate marked Canceled.
        assert!(state.outputs.iter().all(|o| !o.is_reserved()));
        assert_eq!(state.pending_slates[0].status, SlateLifecycle::Canceled);
    }
}
