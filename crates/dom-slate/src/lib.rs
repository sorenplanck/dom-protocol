//! # dom-slate
//!
//! Pure interactive Mimblewimble slate crypto for the DOM Protocol: the
//! sender build (step 1), recipient response (step 2), and sender finalize
//! (step 3) of the slate protocol, plus the kernel/aggregation helpers they
//! share.
//!
//! ## Why this crate exists
//!
//! The slate crypto was historically inlined in `dom-wallet::wallet` and
//! mixed with persistence (coin reservation, pending records, the journal,
//! disk writes). This crate is the **single source of truth** for that
//! validated crypto, consumed by both the current `dom-wallet` (as thin
//! wrappers) and the redesigned `dom-wallet2`. Extracting it removes the
//! risk of two divergent copies of audited cryptography.
//!
//! ## Purity contract
//!
//! Every function here is **pure crypto**: material in, `Slate`/`Transaction`
//! out (plus the secrets the caller must persist). Nothing in this crate
//! touches disk, a wallet, the journal, or any persistent state. Coin
//! selection, input reservation, and persistence are the caller's job.
//!
//! Randomness: the change/recipient blindings, the sender/recipient offsets,
//! and the per-session Schnorr nonces are fresh CSPRNG output and single-use.
//! Deterministic (RFC6979-style) nonces are unsafe in aggregate signing —
//! nonce reuse across sessions leaks the signing key — so they are never used.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_consensus::{validate_balance_equation, validate_transaction_structure};
use dom_core::{Amount, KERNEL_FEAT_PLAIN};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{
    blake2b_256_tagged, bp2_prove, bp2_verify, schnorr_add_public_keys, schnorr_aggregate_sigs,
    schnorr_partial_sign, schnorr_verify, BlindingFactor, Hash256, RangeProof, SecretKey,
};
use dom_tx::slate::{OutputCommitmentAndProof, Slate, CURRENT_SLATE_VERSION};
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use rand::RngCore;
use thiserror::Error;

/// Errors arising from slate construction, response, or finalization.
///
/// `Display` strings are stable enough for callers to match on substrings
/// (e.g. the wallet's `chain_id` mismatch test asserts the message contains
/// `"chain_id"`).
#[derive(Debug, Error)]
pub enum SlateError {
    /// The slate's wire format version is unsupported.
    #[error("unsupported slate version {0} (expected {1})")]
    UnsupportedVersion(u16, u16),

    /// The slate's `chain_id` does not match the expected chain.
    #[error("slate chain_id does not match expected chain_id")]
    ChainIdMismatch,

    /// A receive was attempted on a slate that already carries recipient
    /// response fields.
    #[error("slate already contains recipient response fields")]
    RecipientFieldsPresent,

    /// Finalization was attempted on a slate missing a recipient field.
    #[error("slate missing recipient {0}")]
    MissingRecipientField(&'static str),

    /// The aggregate signature failed verification on the finished tx.
    #[error("final slate aggregate signature verification failed")]
    SignatureVerificationFailed,

    /// A cryptographic or validation step failed. The string preserves the
    /// underlying error for operator diagnostics.
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Sender-side input descriptor for [`build_send`].
///
/// The caller (which owns coin selection and the persisted output set)
/// supplies the input commitment and its blinding. Value/maturity decisions
/// are the caller's; this crate only does the slate crypto.
#[derive(Clone)]
pub struct SlateInput {
    /// Compressed 33-byte Pedersen commitment of the input being spent.
    pub commitment: [u8; 33],
    /// 32-byte blinding factor of the input being spent.
    pub blinding: [u8; 32],
}

/// Self-spend change material the caller must persist (the proof itself is
/// carried inside the returned slate's `sender_change_output`).
#[derive(Clone)]
pub struct ChangeMaterial {
    /// Compressed 33-byte Pedersen commitment of the change output.
    pub commitment: [u8; 33],
    /// Change value in noms.
    pub value: u64,
    /// 32-byte random blinding factor for the change output.
    pub blinding: [u8; 32],
}

/// Result of [`build_send`] — the public slate plus the sender secrets the
/// caller must persist (only inside encrypted wallet state) and the optional
/// change material.
pub struct SenderSlate {
    /// The step-1 slate to hand to the recipient. Contains only public data.
    pub slate: Slate,
    /// Sender excess blinding `x_S` for the aggregate kernel key. Secret.
    pub excess_blinding: [u8; 32],
    /// Random single-use sender nonce `k_S`. Secret; discard after finalize.
    pub nonce: [u8; 32],
    /// Self-spend change to register once the tx confirms. `None` for exact
    /// spends (no change).
    pub change: Option<ChangeMaterial>,
}

/// Result of [`respond_receive`] — the answered slate plus the recipient's
/// output blinding the caller must persist to later spend the received output.
pub struct ReceiveResponse {
    /// The step-2 slate to hand back to the sender. Contains only public data.
    pub slate: Slate,
    /// Recipient output blinding `x_R`. Secret; never exported or journaled.
    pub recipient_output_blinding: [u8; 32],
}

/// Step 1: build a sender slate from selected inputs.
///
/// Produces the random change output (if `change_value > 0`), the sender
/// offset, excess, and single-use nonce, and assembles the public slate. The
/// returned [`SenderSlate`] carries the secrets the caller must persist.
///
/// `change_value` is computed by the caller from its coin selection
/// (`sum(inputs) - amount - fee`); a value of `0` means no change output.
pub fn build_send(
    inputs: &[SlateInput],
    change_value: u64,
    amount: u64,
    fee: u64,
    chain_id: [u8; 32],
) -> Result<SenderSlate, SlateError> {
    let (sender_change_output, change_material, change_blinding) = if change_value > 0 {
        let change_blinding = BlindingFactor::random();
        // Standard Bulletproof (bp2): returns proof bytes; wrap into RangeProof
        // for the slate's OutputCommitmentAndProof field.
        let (proof_bytes, commitment_bytes) = bp2_prove(change_value, &change_blinding)
            .map_err(|e| SlateError::Crypto(format!("change range proof failed: {e}")))?;
        let proof = RangeProof::from_bytes(proof_bytes)
            .map_err(|e| SlateError::Crypto(format!("change range proof invalid: {e}")))?;
        let change_commitment = Commitment::from_compressed_bytes(&commitment_bytes)
            .map_err(|e| SlateError::Crypto(format!("change commitment invalid: {e}")))?;
        (
            Some(OutputCommitmentAndProof {
                commitment: change_commitment,
                proof,
            }),
            Some(ChangeMaterial {
                commitment: commitment_bytes,
                value: change_value,
                blinding: *change_blinding.as_bytes(),
            }),
            Some(change_blinding),
        )
    } else {
        (None, None, None)
    };

    let sender_offset = BlindingFactor::random();
    let excess_blinding = sender_excess_blinding(
        inputs.iter().map(|i| &i.blinding),
        change_blinding.as_ref().map(|b| b.as_bytes()),
        sender_offset.as_bytes(),
    )?;
    let sender_excess_key = SecretKey::from_bytes(&excess_blinding)
        .map_err(|e| SlateError::Crypto(format!("sender excess key invalid: {e}")))?;

    // Multisignature Schnorr nonces must be fresh CSPRNG output and
    // single-use. RFC6979-style deterministic nonces are unsafe here: if a
    // nonce is reused across aggregate-signing sessions, the sender excess
    // private key can be recovered. The caller persists this nonce only in
    // encrypted wallet state and discards it after finalize.
    let sender_nonce_key = random_secret_key();
    let sender_nonce = sender_nonce_key.to_be_bytes_raw();

    let slate = Slate {
        version: CURRENT_SLATE_VERSION,
        chain_id,
        amount,
        fee,
        lock_height: 0,
        sender_inputs: inputs
            .iter()
            .map(|i| Commitment::from_compressed_bytes(&i.commitment))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SlateError::Crypto(format!("sender input commitment invalid: {e}")))?,
        sender_change_output,
        sender_public_excess: sender_excess_key.public_key(),
        sender_public_nonce: sender_nonce_key.public_key(),
        sender_offset_contribution: *sender_offset.as_bytes(),
        recipient_output: None,
        recipient_public_excess: None,
        recipient_public_nonce: None,
        sender_partial_sig: None,
        recipient_partial_sig: None,
    };

    Ok(SenderSlate {
        slate,
        excess_blinding,
        nonce: sender_nonce,
        change: change_material,
    })
}

/// Step 2: respond to a sender-created interactive slate.
///
/// Rejects cross-chain slates and slates already carrying recipient fields,
/// creates the recipient output and range proof, generates a fresh single-use
/// recipient nonce, partially signs the aggregate kernel message, and returns
/// the answered slate plus the recipient output blinding to persist.
pub fn respond_receive(
    mut slate: Slate,
    expected_chain_id: &[u8; 32],
) -> Result<ReceiveResponse, SlateError> {
    validate_slate_version(&slate)?;
    if slate.chain_id != *expected_chain_id {
        return Err(SlateError::ChainIdMismatch);
    }
    if slate.recipient_output.is_some()
        || slate.recipient_public_excess.is_some()
        || slate.recipient_public_nonce.is_some()
        || slate.recipient_partial_sig.is_some()
    {
        return Err(SlateError::RecipientFieldsPresent);
    }

    Amount::from_noms(slate.amount)
        .map_err(|e| SlateError::Crypto(format!("invalid slate amount: {e}")))?;
    Amount::from_noms(slate.fee)
        .map_err(|e| SlateError::Crypto(format!("invalid slate fee: {e}")))?;

    let recipient_blinding = BlindingFactor::random();
    // Standard Bulletproof (bp2): wrap proof bytes into RangeProof for the slate.
    let (proof_bytes, commitment_bytes) = bp2_prove(slate.amount, &recipient_blinding)
        .map_err(|e| SlateError::Crypto(format!("recipient range proof failed: {e}")))?;
    let proof = RangeProof::from_bytes(proof_bytes)
        .map_err(|e| SlateError::Crypto(format!("recipient range proof invalid: {e}")))?;
    let recipient_output = OutputCommitmentAndProof {
        commitment: Commitment::from_compressed_bytes(&commitment_bytes)
            .map_err(|e| SlateError::Crypto(format!("recipient commitment invalid: {e}")))?,
        proof,
    };
    let recipient_excess_key = SecretKey::from_bytes(recipient_blinding.as_bytes())
        .map_err(|e| SlateError::Crypto(format!("recipient excess key invalid: {e}")))?;
    let recipient_public_excess = recipient_excess_key.public_key();

    // Fresh CSPRNG single-use nonce; consumed immediately for s_R, never
    // exported or persisted (see purity contract).
    let recipient_nonce_key = random_secret_key();
    let recipient_public_nonce = recipient_nonce_key.public_key();

    let agg_r = schnorr_add_public_keys(&[
        slate.sender_public_nonce.clone(),
        recipient_public_nonce.clone(),
    ])
    .map_err(|e| SlateError::Crypto(format!("aggregate nonce failed: {e}")))?;
    let agg_p = schnorr_add_public_keys(&[
        slate.sender_public_excess.clone(),
        recipient_public_excess.clone(),
    ])
    .map_err(|e| SlateError::Crypto(format!("aggregate public excess failed: {e}")))?;
    let kernel_message = plain_kernel_message(slate.fee, slate.lock_height)?;
    let recipient_partial_sig = schnorr_partial_sign(
        &recipient_excess_key,
        &recipient_nonce_key,
        &agg_r,
        &agg_p,
        expected_chain_id,
        kernel_message.as_bytes(),
    )
    .map_err(|e| SlateError::Crypto(format!("recipient partial signature failed: {e}")))?;

    slate.recipient_output = Some(recipient_output);
    slate.recipient_public_excess = Some(recipient_public_excess);
    slate.recipient_public_nonce = Some(recipient_public_nonce);
    slate.recipient_partial_sig = Some(recipient_partial_sig);

    Ok(ReceiveResponse {
        slate,
        recipient_output_blinding: *recipient_blinding.as_bytes(),
    })
}

/// Step 3: finalize a recipient-answered slate into a validated transaction.
///
/// Verifies the recipient response is present, recovers the sender partial
/// signature from the supplied secrets, aggregates the final kernel
/// signature, assembles the transaction, and validates its structure,
/// balance equation, and aggregate signature before returning it.
///
/// Wallet-side ownership/anti-replay checks (matching the slate against a
/// persisted pending sender record and its reserved inputs) are the caller's
/// responsibility and live outside this crate.
pub fn finalize(
    slate: &Slate,
    sender_excess_blinding: &[u8; 32],
    sender_nonce: &[u8; 32],
    chain_id: &[u8; 32],
) -> Result<Transaction, SlateError> {
    validate_slate_version(slate)?;
    if slate.chain_id != *chain_id {
        return Err(SlateError::ChainIdMismatch);
    }

    let recipient_output = slate
        .recipient_output
        .clone()
        .ok_or(SlateError::MissingRecipientField("output"))?;
    let recipient_public_excess = slate
        .recipient_public_excess
        .clone()
        .ok_or(SlateError::MissingRecipientField("public excess"))?;
    let recipient_public_nonce = slate
        .recipient_public_nonce
        .clone()
        .ok_or(SlateError::MissingRecipientField("public nonce"))?;
    let recipient_partial_sig = slate
        .recipient_partial_sig
        .clone()
        .ok_or(SlateError::MissingRecipientField("partial signature"))?;

    let agg_r = schnorr_add_public_keys(&[
        slate.sender_public_nonce.clone(),
        recipient_public_nonce.clone(),
    ])
    .map_err(|e| SlateError::Crypto(format!("aggregate nonce failed: {e}")))?;
    let agg_p = schnorr_add_public_keys(&[
        slate.sender_public_excess.clone(),
        recipient_public_excess.clone(),
    ])
    .map_err(|e| SlateError::Crypto(format!("aggregate excess failed: {e}")))?;
    let kernel_message = plain_kernel_message(slate.fee, slate.lock_height)?;

    let sender_excess_key = SecretKey::from_bytes(sender_excess_blinding)
        .map_err(|e| SlateError::Crypto(format!("sender excess key invalid: {e}")))?;
    let sender_nonce_key = SecretKey::from_bytes(sender_nonce)
        .map_err(|e| SlateError::Crypto(format!("sender nonce invalid: {e}")))?;
    let sender_partial_sig = schnorr_partial_sign(
        &sender_excess_key,
        &sender_nonce_key,
        &agg_r,
        &agg_p,
        chain_id,
        kernel_message.as_bytes(),
    )
    .map_err(|e| SlateError::Crypto(format!("sender partial signature failed: {e}")))?;
    let aggregate_sig =
        schnorr_aggregate_sigs(&[sender_partial_sig, recipient_partial_sig], &agg_r)
            .map_err(|e| SlateError::Crypto(format!("aggregate signature failed: {e}")))?;

    let tx = Transaction {
        inputs: slate
            .sender_inputs
            .iter()
            .cloned()
            .map(|commitment| TransactionInput { commitment })
            .collect(),
        outputs: slate_outputs(slate, recipient_output),
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(slate.fee)
                .map_err(|e| SlateError::Crypto(format!("invalid kernel fee: {e}")))?,
            lock_height: slate.lock_height,
            excess: Commitment::from_compressed_bytes(&agg_p.to_compressed_bytes())
                .map_err(|e| SlateError::Crypto(format!("kernel excess invalid: {e}")))?,
            excess_signature: aggregate_sig.to_bytes(),
        }],
        offset: slate.sender_offset_contribution,
    };

    validate_transaction_structure(&tx)
        .map_err(|e| SlateError::Crypto(format!("final slate tx structure invalid: {e}")))?;
    for output in &tx.outputs {
        let proof_ok = bp2_verify(output.commitment.as_bytes(), &output.proof)
            .map_err(|e| SlateError::Crypto(format!("final slate range proof invalid: {e}")))?;
        if !proof_ok {
            return Err(SlateError::Crypto(
                "final slate output range proof does not verify".into(),
            ));
        }
    }
    validate_balance_equation(&tx)
        .map_err(|e| SlateError::Crypto(format!("final slate tx balance invalid: {e}")))?;
    if !schnorr_verify(&aggregate_sig, &agg_p, chain_id, kernel_message.as_bytes())
        .map_err(|e| SlateError::Crypto(format!("final slate signature invalid: {e}")))?
    {
        return Err(SlateError::SignatureVerificationFailed);
    }

    Ok(tx)
}

/// Reconstruct the sender (step-1) view of a slate by stripping all recipient
/// response fields. Used to recompute the sender slate hash a caller can key
/// its persisted pending record by.
pub fn sender_phase_slate(slate: &Slate) -> Slate {
    Slate {
        version: slate.version,
        chain_id: slate.chain_id,
        amount: slate.amount,
        fee: slate.fee,
        lock_height: slate.lock_height,
        sender_inputs: slate.sender_inputs.clone(),
        sender_change_output: slate.sender_change_output.clone(),
        sender_public_excess: slate.sender_public_excess.clone(),
        sender_public_nonce: slate.sender_public_nonce.clone(),
        sender_offset_contribution: slate.sender_offset_contribution,
        recipient_output: None,
        recipient_public_excess: None,
        recipient_public_nonce: None,
        sender_partial_sig: None,
        recipient_partial_sig: None,
    }
}

/// Canonical plain-kernel signing message: `blake2b_256_tagged(TAG_KERNEL_MSG,
/// feature || fee_le || lock_height_le)`.
pub fn plain_kernel_message(fee: u64, lock_height: u64) -> Result<Hash256, SlateError> {
    Amount::from_noms(fee).map_err(|e| SlateError::Crypto(format!("invalid kernel fee: {e}")))?;
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    Ok(blake2b_256_tagged(dom_core::TAG_KERNEL_MSG, &data))
}

/// Assemble the transaction outputs for a slate: the optional sender change
/// output followed by the recipient output, in that order.
pub fn slate_outputs(
    slate: &Slate,
    recipient_output: OutputCommitmentAndProof,
) -> Vec<TransactionOutput> {
    let mut outputs = Vec::with_capacity(usize::from(slate.sender_change_output.is_some()) + 1);
    if let Some(change) = &slate.sender_change_output {
        outputs.push(TransactionOutput {
            commitment: change.commitment.clone(),
            proof: change.proof.bytes.clone(),
        });
    }
    outputs.push(TransactionOutput {
        commitment: recipient_output.commitment,
        proof: recipient_output.proof.bytes,
    });
    outputs
}

/// Compute the sender excess blinding `x_S = change - sum(inputs) - offset`
/// over the secp256k1 scalar field. Returns an error if the result is zero
/// (a degenerate excess that cannot key the aggregate kernel).
pub fn sender_excess_blinding<'a, I>(
    input_blindings: I,
    change_blinding: Option<&[u8; 32]>,
    sender_offset: &[u8; 32],
) -> Result<[u8; 32], SlateError>
where
    I: IntoIterator<Item = &'a [u8; 32]>,
{
    let mut acc = Scalar::ZERO;

    if let Some(change_blinding) = change_blinding {
        acc += scalar_from_bytes(change_blinding)?;
    }
    for blinding in input_blindings {
        acc -= scalar_from_bytes(blinding)?;
    }
    acc -= scalar_from_bytes(sender_offset)?;

    if bool::from(acc.is_zero()) {
        return Err(SlateError::Crypto(
            "sender excess blinding unexpectedly became zero".into(),
        ));
    }

    Ok(acc.to_repr().into())
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, SlateError> {
    let repr = k256::FieldBytes::from(*bytes);
    let scalar = Scalar::from_repr(repr);
    if scalar.is_some().into() {
        Ok(scalar.unwrap())
    } else {
        Err(SlateError::Crypto("invalid scalar bytes".into()))
    }
}

fn validate_slate_version(slate: &Slate) -> Result<(), SlateError> {
    if slate.version != CURRENT_SLATE_VERSION {
        return Err(SlateError::UnsupportedVersion(
            slate.version,
            CURRENT_SLATE_VERSION,
        ));
    }
    Ok(())
}

/// Generate a fresh random secp256k1 secret key via rejection sampling.
pub fn random_secret_key() -> SecretKey {
    let mut bytes = [0u8; 32];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(secret_key) = SecretKey::from_bytes(&bytes) {
            return secret_key;
        }
    }
}
