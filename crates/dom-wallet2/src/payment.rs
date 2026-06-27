//! Interactive payment orchestration (design §5.2 / §2.5) — slate → store.
//!
//! These are **pure state transitions** over [`WalletV2State`] (no disk I/O — the
//! caller persists via [`crate::save_wallet_state`]). The crypto is the shared,
//! pure [`dom_slate`]; this layer does coin selection, the C0 inserts, input
//! reservation, the cancel path, and the receiver / finalize steps.
//!
//! **Atomicity:** every action validates and calls `dom-slate` *before* it
//! mutates the state, so an early error (insufficient funds, slate failure)
//! leaves the state **untouched** — nothing is reserved, inserted, or wiped.
//!
//! The full flow: [`create_send`] (sender, C0 change) → [`receive`] (receiver,
//! C0 recipient) → [`finalize`] (sender closes, wipes the secrets) → the returned
//! `Transaction` goes to the node. [`cancel`] undoes a still-Unconfirmed send.

use crate::pending::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
use crate::store::StoreError;
use crate::tx_sink::{SubmitOutcome, TxSink};
use crate::types::{OutputOrigin, OutputStatus, StoredOutput};
use crate::wallet_state::WalletV2State;
use dom_consensus::transaction::Transaction;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_slate::{build_send, finalize as slate_finalize, respond_receive, sender_phase_slate};
use dom_slate::{SlateError, SlateInput};
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
    /// The answered slate is missing the recipient output (malformed response).
    #[error("answered slate missing recipient output")]
    MissingRecipientOutput,
    /// The pending sender slate has no usable secrets (already finalized/cleared).
    #[error("pending sender slate has no secrets (already finalized?)")]
    SecretsUnavailable,
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

    let total = candidates.iter().try_fold(0u64, |acc, output| {
        acc.checked_add(output.value)
            .ok_or(PaymentError::AmountOverflow)
    })?;
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
        sum = sum
            .checked_add(o.value)
            .ok_or(PaymentError::AmountOverflow)?;
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
        secrets: Some(SlateSecrets::Sender {
            excess_blinding: Zeroizing::new(sender.excess_blinding),
            nonce: Zeroizing::new(sender.nonce),
        }),
        reserved_inputs: selected.clone(),
        produced_output,
        finalized_tx: None,
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

/// Receiver step: answer a sender-created slate, creating the recipient output in
/// the store at C0 (design §5.2). The recipient amount is **known** — it is
/// `slate.amount` (carried in the slate) — so the output is fully reconstructed
/// (unlike seed restore, which lacks the amount).
///
/// On success the state gains a `StoredOutput{ReceiveSlate, Unconfirmed}` (random
/// blinding persisted) and a `PendingSlate{Receiver}`. Returns the answered slate
/// to hand back to the sender. On any error the state is untouched (the crypto
/// runs before any mutation).
pub fn receive(state: &mut WalletV2State, slate: Slate, now: u64) -> Result<Slate, PaymentError> {
    // 1) Crypto first (fallible): validates chain_id, builds the recipient output.
    let resp = respond_receive(slate, &state.chain_id)?;
    let commitment = *resp
        .slate
        .recipient_output
        .as_ref()
        .ok_or(PaymentError::MissingRecipientOutput)?
        .commitment
        .as_bytes();
    let value = resp.slate.amount; // the receiver knows the amount
    let slate_bytes = resp
        .slate
        .to_bytes()
        .map_err(|e| PaymentError::Serialization(e.to_string()))?;
    let slate_hash = *dom_crypto::blake2b_256(&slate_bytes).as_bytes();

    // 2) Mutate: C0 recipient output + pending receiver slate.
    state
        .outputs
        .insert(StoredOutput::new_unconfirmed(
            commitment,
            value,
            resp.recipient_output_blinding,
            OutputOrigin::ReceiveSlate,
            false,
            None,
            now,
        ))
        .map_err(PaymentError::Store)?;

    state.pending_slates.push(PendingSlate {
        slate_hash,
        role: SlateRole::Receiver,
        slate_bytes,
        secrets: Some(SlateSecrets::Receiver {
            output_blinding: Zeroizing::new(resp.recipient_output_blinding),
        }),
        reserved_inputs: Vec::new(),
        produced_output: Some(commitment),
        finalized_tx: None,
        status: SlateLifecycle::Built,
    });

    Ok(resp.slate)
}

/// Sender step 3: finalize a recipient-answered slate into a validated
/// transaction (design §5.2). Looks up our `PendingSlate{Sender}` by the sender
/// phase hash, runs the pure [`dom_slate`] finalize with the stored secrets, and
/// — **only on success** — marks the slate `Finalized` and **wipes the secrets**
/// (the single-use nonce is discarded). No new output is created; the change was
/// born at C0 in `create_send`.
///
/// **Atomicity:** if the crypto fails, the pending slate is left `Built` with its
/// secrets intact, so the caller can retry. Returns the `Transaction` to submit
/// to the network (submission itself is out of scope).
pub fn finalize(
    state: &mut WalletV2State,
    answered_slate: Slate,
    now: u64,
) -> Result<Transaction, PaymentError> {
    finalize_tracked(state, answered_slate, now).map(|(tx, _hash)| tx)
}

/// Like [`finalize`], but also returns the sender slate hash — the key
/// [`submit_finalized`] needs to find and advance this slate.
///
/// `finalize` derives that hash internally (from the answered slate's step-1
/// phase) and then discards it; a caller that wants to submit right after
/// finalizing would otherwise have to re-derive it by reaching into
/// `dom-slate`. Exposing it here keeps the hash derivation single-sourced. The
/// behaviour is otherwise identical to [`finalize`] (same atomicity: on a crypto
/// error the slate is left `Built` with its secrets intact, retryable).
pub fn finalize_tracked(
    state: &mut WalletV2State,
    answered_slate: Slate,
    _now: u64,
) -> Result<(Transaction, [u8; 32]), PaymentError> {
    // 1) Locate our pending sender slate by the sender (step-1) phase hash.
    let sender_bytes = sender_phase_slate(&answered_slate)
        .to_bytes()
        .map_err(|e| PaymentError::Serialization(e.to_string()))?;
    let sender_hash = *dom_crypto::blake2b_256(&sender_bytes).as_bytes();
    let idx = state
        .pending_slates
        .iter()
        .position(|p| p.slate_hash == sender_hash && p.role == SlateRole::Sender)
        .ok_or(PaymentError::NotFound)?;

    // Copy the secrets into zeroizing locals (wiped when this fn returns).
    let (excess, nonce) = match state.pending_slates[idx].secrets.as_ref() {
        Some(SlateSecrets::Sender {
            excess_blinding,
            nonce,
        }) => (Zeroizing::new(**excess_blinding), Zeroizing::new(**nonce)),
        _ => return Err(PaymentError::SecretsUnavailable),
    };

    // 2) Crypto FIRST (fallible) — state not yet mutated.
    let tx = slate_finalize(&answered_slate, &excess, &nonce, &state.chain_id)?;
    // Persist the (public) tx bytes so it can be submitted/resubmitted even
    // though finalize is about to wipe the secrets (it cannot run twice).
    let tx_bytes = tx
        .to_bytes()
        .map_err(|e| PaymentError::Serialization(e.to_string()))?;

    // 3) Success only: mark Finalized, persist the tx, WIPE the secrets.
    state.pending_slates[idx].status = SlateLifecycle::Finalized;
    state.pending_slates[idx].finalized_tx = Some(tx_bytes);
    state.pending_slates[idx].secrets = None;

    Ok((tx, sender_hash))
}

/// Error from [`submit_finalized`]. Wraps the sink's transport error plus the
/// wallet-level lookup/decoding errors.
#[derive(Debug, thiserror::Error)]
pub enum SubmitError<E: std::error::Error + 'static> {
    /// No sender slate with this hash.
    #[error("pending sender slate not found")]
    NotFound,
    /// The slate has not been finalized (no tx to submit).
    #[error("slate is not finalized; nothing to submit")]
    NotFinalized,
    /// The persisted tx bytes failed to decode.
    #[error("stored tx decode failed: {0}")]
    Decode(String),
    /// The transport (TxSink) failed.
    #[error(transparent)]
    Sink(#[from] E),
}

/// Submit a finalized sender slate's transaction to the network and, **only on
/// success**, advance it `Finalized -> Submitted`.
///
/// Reads the persisted `finalized_tx` (no secrets needed — they were wiped at
/// finalize), so it works after a restart / resubmit. The [`TxSink`] is pure
/// transport: it never touches state. **Atomicity:** the network call happens
/// first; on a reject the slate stays `Finalized` (retryable / inspectable) and
/// the reservation is released (R-31(c), below) — a rejection is surfaced, never
/// guessed into `Failed` (the next `reconcile` establishes the truth).
pub fn submit_finalized<S: TxSink>(
    state: &mut WalletV2State,
    sink: &S,
    slate_hash: [u8; 32],
    now: u64,
) -> Result<SubmitOutcome, SubmitError<S::Error>> {
    let idx = state
        .pending_slates
        .iter()
        .position(|p| p.slate_hash == slate_hash && p.role == SlateRole::Sender)
        .ok_or(SubmitError::NotFound)?;

    let bytes = state.pending_slates[idx]
        .finalized_tx
        .clone()
        .ok_or(SubmitError::NotFinalized)?;
    let tx = Transaction::from_bytes(&bytes).map_err(|e| SubmitError::Decode(e.to_string()))?;

    // Network first.
    let outcome = match sink.submit_tx(&tx) {
        Ok(o) => o,
        Err(e) => {
            // R-31(c): node rejected the tx — release the input reservations so they
            // are not left stuck. Do NOT mark Failed: a reject does not prove the tx is
            // dead; the next reconcile establishes the truth (Spent if it landed,
            // Confirmed if not). The reservation is only a local double-spend guard and
            // is safe to release here.
            let reserved = state.pending_slates[idx].reserved_inputs.clone();
            for c in &reserved {
                if let Some(out) = state.outputs.get_mut(c) {
                    out.release_reservation(now);
                }
            }
            return Err(SubmitError::from(e));
        }
    };

    state.pending_slates[idx].status = SlateLifecycle::Submitted;
    Ok(outcome)
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

    // ── Receiver + finalize + end-to-end ────────────────────────────────────

    const CHAIN_ID: [u8; 32] = [0x77u8; 32];

    /// An empty receiver wallet on the same chain as `funded_state`.
    fn receiver_state() -> WalletV2State {
        let mut s = WalletV2State::new(Network::Regtest, CHAIN_ID);
        s.meta.last_reconciled_tip = 100;
        s
    }

    #[test]
    fn receive_creates_recipient_c0_with_slate_amount() {
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();

        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();

        // The recipient output is born at C0 with the slate's amount.
        let rc = recv.pending_slates[0].produced_output.unwrap();
        let out = recv.outputs.get(&rc).unwrap();
        assert_eq!(out.value, 1000, "recipient value is slate.amount");
        assert_eq!(out.origin, OutputOrigin::ReceiveSlate);
        assert_eq!(out.status, OutputStatus::Unconfirmed);
        // The C0 commitment matches the one in the answered slate.
        let slate_rc = answered.recipient_output.as_ref().unwrap();
        assert_eq!(out.commitment, *slate_rc.commitment.as_bytes());
        assert_eq!(recv.pending_slates[0].role, SlateRole::Receiver);
    }

    #[test]
    fn finalize_success_marks_finalized_and_wipes_secrets() {
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();

        let _tx = finalize(&mut sender, answered, 4000).unwrap();

        // Sender slate is Finalized and its secrets are WIPED (nonce discarded).
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        assert!(
            sender.pending_slates[0].secrets.is_none(),
            "secrets must be wiped after a successful finalize"
        );
    }

    #[test]
    fn finalize_error_preserves_secrets_retryable() {
        // Finalizing the step-1 slate (no recipient fields) must fail — and leave
        // the pending slate Built with its secrets intact, so a retry works.
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();

        let err = finalize(&mut sender, sent.slate, 4000).unwrap_err();
        assert!(matches!(err, PaymentError::Slate(_)), "got {err:?}");
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Built);
        assert!(
            sender.pending_slates[0].secrets.is_some(),
            "secrets must be preserved on a failed finalize (retryable)"
        );
    }

    #[test]
    fn double_finalize_refused() {
        // A second finalize of the SAME sender slate must be refused: the first
        // success wiped (x_S, k_S), so there is nothing to re-derive a partial
        // signature from. This is the anti-replay that prevents a second partial
        // sig with the same nonce k_S (which would leak the excess key x_S).
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();

        // First finalize succeeds and wipes the secrets.
        let _tx = finalize(&mut sender, answered.clone(), 4000).unwrap();
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        assert!(
            sender.pending_slates[0].secrets.is_none(),
            "first finalize must wipe the secrets"
        );

        // Second finalize of the same answered slate finds the same (now
        // Finalized) record but has no secrets to sign with → SecretsUnavailable.
        let err = finalize(&mut sender, answered, 4001).unwrap_err();
        assert!(
            matches!(err, PaymentError::SecretsUnavailable),
            "second finalize must be refused (secrets discarded, not re-derivable); got {err:?}"
        );
        // The slate stays terminally Finalized; nothing was re-derived.
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        assert!(sender.pending_slates[0].secrets.is_none());
    }

    #[test]
    fn end_to_end_tx_contains_both_c0_commitments() {
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let change_c = sender.pending_slates[0].produced_output.unwrap();
        let reserved = sender.pending_slates[0].reserved_inputs.clone();

        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();
        let recipient_c = recv.pending_slates[0].produced_output.unwrap();

        let tx = finalize(&mut sender, answered, 4000).unwrap();

        // THE guarantee at the tx level: the finalized tx's outputs are exactly
        // the two C0 outputs the two wallets registered.
        let tx_outs: Vec<[u8; 33]> = tx
            .outputs
            .iter()
            .map(|o| *o.commitment.as_bytes())
            .collect();
        assert!(
            tx_outs.contains(&change_c),
            "tx must contain the sender's C0 change"
        );
        assert!(
            tx_outs.contains(&recipient_c),
            "tx must contain the receiver's C0 recipient output"
        );
        // And the tx spends exactly the reserved inputs.
        let tx_ins: Vec<[u8; 33]> = tx.inputs.iter().map(|i| *i.commitment.as_bytes()).collect();
        assert_eq!(tx_ins.len(), reserved.len());
        for c in &reserved {
            assert!(tx_ins.contains(c), "tx must spend the reserved input");
        }
    }

    #[test]
    fn slate_outputs_survive_reorg_via_real_slate_path() {
        use crate::reconcile::{reconcile, CanonicalView, ScanBlock};

        // Run the real interactive flow, then prove both produced outputs survive
        // a reorg + re-mine through the reconciler.
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let change_c = sender.pending_slates[0].produced_output.unwrap();
        let change_blinding = *sender.outputs.get(&change_c).unwrap().blinding;

        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();
        let recipient_c = recv.pending_slates[0].produced_output.unwrap();
        let recipient_blinding = *recv.outputs.get(&recipient_c).unwrap().blinding;

        let _tx = finalize(&mut sender, answered, 4000).unwrap();

        // Both wallets see the tx mined at block 5.
        let mined = CanonicalView::from_blocks(&[ScanBlock {
            height: 5,
            hash: [5u8; 32],
            output_commitments: vec![change_c, recipient_c],
            input_commitments: vec![],
        }]);
        reconcile(&mut sender.outputs, &mined, 5000);
        reconcile(&mut recv.outputs, &mined, 5000);
        assert_eq!(
            sender.outputs.get(&change_c).unwrap().status,
            OutputStatus::Confirmed
        );
        assert_eq!(
            recv.outputs.get(&recipient_c).unwrap().status,
            OutputStatus::Confirmed
        );

        // Reorg: block 5 leaves — both go Reorged, blindings kept.
        reconcile(&mut sender.outputs, &CanonicalView::empty(), 6000);
        reconcile(&mut recv.outputs, &CanonicalView::empty(), 6000);
        assert_eq!(
            sender.outputs.get(&change_c).unwrap().status,
            OutputStatus::Reorged
        );
        assert_eq!(
            recv.outputs.get(&recipient_c).unwrap().status,
            OutputStatus::Reorged
        );
        assert_eq!(
            *sender.outputs.get(&change_c).unwrap().blinding,
            change_blinding
        );
        assert_eq!(
            *recv.outputs.get(&recipient_c).unwrap().blinding,
            recipient_blinding
        );

        // Re-mine at block 5' — both re-confirm from persisted material.
        let remined = CanonicalView::from_blocks(&[ScanBlock {
            height: 5,
            hash: [0x5bu8; 32],
            output_commitments: vec![change_c, recipient_c],
            input_commitments: vec![],
        }]);
        reconcile(&mut sender.outputs, &remined, 7000);
        reconcile(&mut recv.outputs, &remined, 7000);
        assert_eq!(
            sender.outputs.get(&change_c).unwrap().status,
            OutputStatus::Confirmed
        );
        assert_eq!(
            recv.outputs.get(&recipient_c).unwrap().status,
            OutputStatus::Confirmed
        );
        // The funds survived end to end via the real slate path.
        assert_eq!(
            *sender.outputs.get(&change_c).unwrap().blinding,
            change_blinding
        );
        assert_eq!(
            *recv.outputs.get(&recipient_c).unwrap().blinding,
            recipient_blinding
        );
    }

    // ── submit_finalized (orchestration over a TxSink) ──────────────────────

    use crate::tx_sink::InMemoryTxSink;

    /// Run the real interactive flow to a finalized sender slate, returning the
    /// sender state and the sender slate's hash.
    fn finalized_sender() -> (WalletV2State, [u8; 32]) {
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let hash = sent.slate_hash;
        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();
        let _tx = finalize(&mut sender, answered, 4000).unwrap();
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        (sender, hash)
    }

    #[test]
    fn submit_accepted_advances_to_submitted() {
        let (mut sender, hash) = finalized_sender();
        let sink = InMemoryTxSink::accepting([0x42u8; 32]);

        let out = submit_finalized(&mut sender, &sink, hash, 5000).unwrap();

        assert_eq!(out.tx_hash, [0x42u8; 32]);
        assert!(out.relayed);
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Submitted);
        assert_eq!(sink.calls(), 1);
    }

    #[test]
    fn submit_not_relayed_still_submitted_with_warning_preserved() {
        let (mut sender, hash) = finalized_sender();
        let sink = InMemoryTxSink::accepting_not_relayed([0x99u8; 32], "accepted but not relayed");

        let out = submit_finalized(&mut sender, &sink, hash, 5000).unwrap();

        // Accepted-but-not-relayed is still success: state advances and the
        // node's advisory is surfaced verbatim for the caller to act on.
        assert!(!out.relayed);
        assert_eq!(out.warning.as_deref(), Some("accepted but not relayed"));
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Submitted);
    }

    #[test]
    fn submit_rejected_keeps_state_finalized_and_surfaces_error() {
        let (mut sender, hash) = finalized_sender();
        let sink = InMemoryTxSink::rejecting("tx rejected: invalid kernel");

        let err = submit_finalized(&mut sender, &sink, hash, 5000).unwrap_err();

        // The rejection is surfaced (never auto-Failed), and the slate stays
        // Finalized so the tx can be inspected / resubmitted.
        match err {
            SubmitError::Sink(e) => assert!(e.to_string().contains("invalid kernel"), "{e}"),
            other => panic!("expected Sink error, got {other:?}"),
        }
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        // The persisted tx is intact for a retry.
        assert!(sender.pending_slates[0].finalized_tx.is_some());
    }

    #[test]
    fn reserved_input_released_on_submit_reject() {
        // R-31(c): a node reject must release the input reservations (so they are
        // not left stuck) while keeping the slate Finalized — a reject is not proof
        // the tx is dead; reconcile establishes the truth.
        let (mut sender, hash) = finalized_sender();

        // Precondition: the finalized slate reserved inputs, all currently reserved.
        let reserved = sender.pending_slates[0].reserved_inputs.clone();
        assert!(
            !reserved.is_empty(),
            "precondition: the send reserved inputs"
        );
        assert!(
            reserved
                .iter()
                .all(|c| sender.outputs.get(c).unwrap().is_reserved()),
            "precondition: every selected input is reserved before submit"
        );

        let sink = InMemoryTxSink::rejecting("tx rejected: node says no");
        let err = submit_finalized(&mut sender, &sink, hash, 5000).unwrap_err();

        // (3) The error is propagated, with the node's reason surfaced verbatim.
        match err {
            SubmitError::Sink(e) => assert!(e.to_string().contains("node says no"), "{e}"),
            other => panic!("expected Sink error, got {other:?}"),
        }
        // (1) Every reserved input was released — none is left stuck.
        for c in &reserved {
            assert!(
                !sender.outputs.get(c).unwrap().is_reserved(),
                "reserved input must be released after a submit reject"
            );
        }
        // (2) The slate stays Finalized (NOT Failed/Canceled) — retryable/inspectable,
        // and the persisted tx is intact for a retry/reconcile.
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Finalized);
        assert!(sender.pending_slates[0].finalized_tx.is_some());
    }

    #[test]
    fn submit_reads_persisted_tx_without_secrets() {
        let (mut sender, hash) = finalized_sender();
        // finalize wiped the secrets — submit must not need them.
        assert!(
            sender.pending_slates[0].secrets.is_none(),
            "precondition: secrets were wiped at finalize"
        );
        let sink = InMemoryTxSink::accepting([0x01u8; 32]);
        submit_finalized(&mut sender, &sink, hash, 5000).unwrap();
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Submitted);
    }

    #[test]
    fn finalized_tx_survives_reload_and_resubmits_after_crash() {
        use crate::persist::{load_wallet_state, save_wallet_state};

        let (sender, hash) = finalized_sender();
        let expected_tx = sender.pending_slates[0].finalized_tx.clone().unwrap();

        // Persist (encrypted) and reload — simulating a crash after finalize but
        // before submit. The secrets are gone; only the public tx remains.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dom");
        save_wallet_state(&sender, &path, "pw").unwrap();
        let mut reloaded = load_wallet_state(&path, "pw").unwrap();

        let slate = &reloaded.pending_slates[0];
        assert_eq!(slate.status, SlateLifecycle::Finalized);
        assert!(slate.secrets.is_none(), "secrets must not survive");
        assert_eq!(
            slate.finalized_tx.as_ref(),
            Some(&expected_tx),
            "the public tx must survive the crash for resubmit"
        );

        // Resubmit from the reloaded state works (no secrets required).
        let sink = InMemoryTxSink::accepting([0x55u8; 32]);
        let out = submit_finalized(&mut reloaded, &sink, hash, 5000).unwrap();
        assert_eq!(out.tx_hash, [0x55u8; 32]);
        assert_eq!(reloaded.pending_slates[0].status, SlateLifecycle::Submitted);
    }

    #[test]
    fn finalize_tracked_returns_the_submit_key() {
        // The hash returned by finalize_tracked must be exactly the sender slate
        // hash submit_finalized looks up — proven by submitting with it.
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let mut recv = receiver_state();
        let answered = receive(&mut recv, sent.slate, 3000).unwrap();

        let (_tx, hash) = finalize_tracked(&mut sender, answered, 4000).unwrap();
        assert_eq!(
            hash, sent.slate_hash,
            "tracked hash is the create_send hash"
        );

        let sink = InMemoryTxSink::accepting([0x42u8; 32]);
        submit_finalized(&mut sender, &sink, hash, 5000).unwrap();
        assert_eq!(sender.pending_slates[0].status, SlateLifecycle::Submitted);
    }

    #[test]
    fn submit_unknown_slate_is_not_found() {
        let (mut sender, _hash) = finalized_sender();
        let sink = InMemoryTxSink::accepting([0u8; 32]);
        let err = submit_finalized(&mut sender, &sink, [0xFFu8; 32], 5000).unwrap_err();
        assert!(matches!(err, SubmitError::NotFound), "got {err:?}");
        assert_eq!(sink.calls(), 0, "no submission for an unknown slate");
    }

    #[test]
    fn submit_not_finalized_slate_is_rejected() {
        // A freshly built (not finalized) sender slate has no tx to submit.
        let mut sender = funded_state(&[600, 600]);
        let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
        let sink = InMemoryTxSink::accepting([0u8; 32]);
        let err = submit_finalized(&mut sender, &sink, sent.slate_hash, 5000).unwrap_err();
        assert!(matches!(err, SubmitError::NotFinalized), "got {err:?}");
        assert_eq!(sink.calls(), 0);
    }
}
