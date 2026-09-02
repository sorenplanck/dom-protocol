#![forbid(unsafe_code)]

//! Thin, protocol-pinned boundary for DOM interactive slate operations.
//!
//! This crate intentionally owns no wallet state and exports no wallet secret
//! DTO.  It converts public canonical slate bytes to and from the authoritative
//! DOM serialization and returns private material only to the encrypted core.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dom_consensus::{validate_balance_equation, validate_transaction_structure};
use dom_crypto::bp2_verify;
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use dom_slate::{build_send_with_lock_height, finalize, respond_receive, SlateInput};
use dom_tx::slate::Slate;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

pub const TRANSPORT_PREFIX: &str = "DOMSLATE1.";
pub const QR_FRAME_PREFIX: &str = "DOMQR1.";
pub const MAX_TRANSPORT_BYTES: usize = 1_048_576;
pub const MAX_QR_SINGLE_TEXT_BYTES: usize = 900;
pub const QR_FRAME_PAYLOAD_BYTES: usize = 600;
pub const MAX_QR_FRAMES: usize = 128;
pub const MIN_RELAY_FEE_RATE: u64 = dom_core::MIN_RELAY_FEE_RATE;
pub const MAX_INPUTS: usize = dom_core::MAX_INPUTS_PER_TX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputMaterial {
    pub commitment: [u8; 33],
    pub blinding: [u8; 32],
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeMaterial {
    pub commitment: [u8; 33],
    pub value: u64,
    pub blinding: [u8; 32],
}

/// Private material returned only to encrypted wallet persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct SenderSecrets {
    pub excess_blinding: [u8; 32],
    pub nonce: [u8; 32],
}

impl std::fmt::Debug for SenderSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SenderSecrets(REDACTED)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecipientSecrets {
    pub output_blinding: [u8; 32],
}

impl std::fmt::Debug for RecipientSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecipientSecrets(REDACTED)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderBuild {
    pub slate_bytes: Vec<u8>,
    pub secrets: SenderSecrets,
    pub change: Option<ChangeMaterial>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientResponse {
    pub slate_bytes: Vec<u8>,
    pub recipient_commitment: [u8; 33],
    pub secrets: RecipientSecrets,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedTransaction {
    pub bytes: Vec<u8>,
    pub transaction_hash: [u8; 32],
    pub kernel_excess: [u8; 33],
    pub weight: u32,
    pub fee: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlatePublicDetails {
    pub chain_id: [u8; 32],
    pub amount: u64,
    pub fee: u64,
    pub input_count: usize,
    pub has_sender_change: bool,
    pub has_recipient_response: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportEnvelope {
    pub version: u8,
    pub response: bool,
    pub network: String,
    pub chain_id: [u8; 32],
    pub slate_id: Uuid,
    pub payload: Vec<u8>,
    pub content_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QrEncoding {
    Single {
        text: String,
        content_hash: [u8; 32],
    },
    Multi {
        frames: Vec<String>,
        content_hash: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QrReassemblyStatus {
    pub message_id: Option<[u8; 32]>,
    pub received_frames: u16,
    pub total_frames: u16,
    pub complete_text: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct QrReassembler {
    message_id: Option<[u8; 32]>,
    total_frames: Option<u16>,
    frames: BTreeMap<u16, Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum ProtocolAdapterError {
    #[error("invalid canonical DOM slate or transaction")]
    InvalidCanonicalEncoding,
    #[error("invalid transaction amount or fee")]
    InvalidAmountOrFee,
    #[error("transaction fee is below the authoritative relay floor")]
    FeeTooLow,
    #[error("transaction input material is invalid")]
    InvalidInput,
    #[error("kernel feature and lock height are inconsistent")]
    InvalidKernelConfiguration,
    #[error("DOM protocol rejected slate construction")]
    ProtocolRejected,
    #[error("manual slate envelope is malformed")]
    InvalidTransport,
    #[error("QR frame or reassembly is malformed")]
    InvalidQrFrame,
    #[error("manual slate envelope does not match the expected slate")]
    SlateBindingMismatch,
}

/// Conservative protocol-derived expected weight: selected inputs, optional
/// sender change and recipient output, and one plain kernel.
pub fn expected_weight(
    input_count: usize,
    change_output: bool,
) -> Result<u32, ProtocolAdapterError> {
    let outputs = 1usize
        .checked_add(usize::from(change_output))
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?;
    let inputs = u32::try_from(input_count).map_err(|_| ProtocolAdapterError::InvalidInput)?;
    let outputs = u32::try_from(outputs).map_err(|_| ProtocolAdapterError::InvalidInput)?;
    Ok(inputs
        .saturating_mul(dom_core::WEIGHT_INPUT)
        .saturating_add(outputs.saturating_mul(dom_core::WEIGHT_OUTPUT))
        .saturating_add(dom_core::WEIGHT_KERNEL))
}

pub fn minimum_fee(input_count: usize, change_output: bool) -> Result<u64, ProtocolAdapterError> {
    u64::from(expected_weight(input_count, change_output)?)
        .checked_mul(MIN_RELAY_FEE_RATE)
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)
}

pub fn build_sender(
    inputs: &[InputMaterial],
    amount: u64,
    fee: u64,
    chain_id: [u8; 32],
    kernel_features: Option<u8>,
    lock_height: Option<u64>,
) -> Result<SenderBuild, ProtocolAdapterError> {
    if inputs.is_empty()
        || inputs.len() > MAX_INPUTS
        || amount == 0
        || fee < minimum_fee(inputs.len(), true)?
    {
        return Err(ProtocolAdapterError::InvalidAmountOrFee);
    }
    let mut unique = BTreeSet::new();
    let total = inputs.iter().try_fold(0u64, |sum, input| {
        if !unique.insert(input.commitment) {
            return Err(ProtocolAdapterError::InvalidInput);
        }
        sum.checked_add(input.value)
            .ok_or(ProtocolAdapterError::InvalidAmountOrFee)
    })?;
    let required = amount
        .checked_add(fee)
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?;
    let change_value = total
        .checked_sub(required)
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?;
    let lock_height = resolve_kernel_lock(kernel_features, lock_height)?;
    let built = build_send_with_lock_height(
        &inputs
            .iter()
            .map(|input| SlateInput {
                commitment: input.commitment,
                blinding: input.blinding,
            })
            .collect::<Vec<_>>(),
        change_value,
        amount,
        fee,
        chain_id,
        lock_height,
    )
    .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    let slate_bytes = encode_slate(&built.slate)?;
    Ok(SenderBuild {
        slate_bytes,
        secrets: SenderSecrets {
            excess_blinding: built.excess_blinding,
            nonce: built.nonce,
        },
        change: built.change.map(|change| ChangeMaterial {
            commitment: change.commitment,
            value: change.value,
            blinding: change.blinding,
        }),
    })
}

fn resolve_kernel_lock(
    kernel_features: Option<u8>,
    lock_height: Option<u64>,
) -> Result<u64, ProtocolAdapterError> {
    let lock_height = lock_height.unwrap_or(0);
    match kernel_features {
        None => Ok(lock_height),
        Some(dom_core::KERNEL_FEAT_PLAIN) if lock_height == 0 => Ok(0),
        Some(dom_core::KERNEL_FEAT_HEIGHT_LOCKED) if lock_height != 0 => Ok(lock_height),
        _ => Err(ProtocolAdapterError::InvalidKernelConfiguration),
    }
}

pub fn create_recipient_response(
    slate_bytes: &[u8],
    expected_chain_id: [u8; 32],
) -> Result<RecipientResponse, ProtocolAdapterError> {
    let slate = decode_slate(slate_bytes)?;
    let response = respond_receive(slate, &expected_chain_id)
        .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    let commitment = response
        .slate
        .recipient_output
        .as_ref()
        .ok_or(ProtocolAdapterError::ProtocolRejected)?
        .commitment
        .as_bytes();
    let mut recipient_commitment = [0u8; 33];
    recipient_commitment.copy_from_slice(commitment);
    Ok(RecipientResponse {
        slate_bytes: encode_slate(&response.slate)?,
        recipient_commitment,
        secrets: RecipientSecrets {
            output_blinding: response.recipient_output_blinding,
        },
    })
}

pub fn slate_public_details(
    slate_bytes: &[u8],
) -> Result<SlatePublicDetails, ProtocolAdapterError> {
    let slate = decode_slate(slate_bytes)?;
    Ok(SlatePublicDetails {
        chain_id: slate.chain_id,
        amount: slate.amount,
        fee: slate.fee,
        input_count: slate.sender_inputs.len(),
        has_sender_change: slate.sender_change_output.is_some(),
        has_recipient_response: slate.recipient_output.is_some()
            || slate.recipient_public_excess.is_some()
            || slate.recipient_public_nonce.is_some()
            || slate.recipient_partial_sig.is_some(),
    })
}

pub fn finalize_sender(
    response_bytes: &[u8],
    expected_request_bytes: &[u8],
    secrets: &SenderSecrets,
    chain_id: [u8; 32],
) -> Result<FinalizedTransaction, ProtocolAdapterError> {
    let response = decode_slate(response_bytes)?;
    let expected = decode_slate(expected_request_bytes)?;
    let stripped = dom_slate::sender_phase_slate(&response);
    if encode_slate(&stripped)? != encode_slate(&expected)? {
        return Err(ProtocolAdapterError::SlateBindingMismatch);
    }
    let tx = finalize(
        &response,
        &secrets.excess_blinding,
        &secrets.nonce,
        &chain_id,
    )
    .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    let weight = tx.weight();
    let fee = tx
        .total_fee()
        .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    if fee
        < u64::from(weight)
            .checked_mul(MIN_RELAY_FEE_RATE)
            .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?
    {
        return Err(ProtocolAdapterError::FeeTooLow);
    }
    validate_transaction(&tx)?;
    let bytes = encode_transaction(&tx)?;
    let kernel = tx
        .kernels
        .first()
        .ok_or(ProtocolAdapterError::ProtocolRejected)?
        .excess
        .as_bytes();
    let mut kernel_excess = [0u8; 33];
    kernel_excess.copy_from_slice(kernel);
    let transaction_hash = *dom_crypto::blake2b_256(&bytes).as_bytes();
    Ok(FinalizedTransaction {
        bytes,
        transaction_hash,
        kernel_excess,
        weight,
        fee,
    })
}

pub fn validate_finalized_bytes(
    bytes: &[u8],
) -> Result<FinalizedTransaction, ProtocolAdapterError> {
    let tx = decode_transaction(bytes)?;
    validate_transaction(&tx)?;
    let weight = tx.weight();
    let fee = tx
        .total_fee()
        .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    if fee
        < u64::from(weight)
            .checked_mul(MIN_RELAY_FEE_RATE)
            .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?
    {
        return Err(ProtocolAdapterError::FeeTooLow);
    }
    let kernel = tx
        .kernels
        .first()
        .ok_or(ProtocolAdapterError::ProtocolRejected)?
        .excess
        .as_bytes();
    let mut kernel_excess = [0u8; 33];
    kernel_excess.copy_from_slice(kernel);
    let transaction_hash = *dom_crypto::blake2b_256(bytes).as_bytes();
    Ok(FinalizedTransaction {
        bytes: bytes.to_vec(),
        transaction_hash,
        kernel_excess,
        weight,
        fee,
    })
}

pub fn export_transport(
    network: &str,
    chain_id: [u8; 32],
    slate_id: Uuid,
    response: bool,
    slate_bytes: &[u8],
) -> Result<String, ProtocolAdapterError> {
    if slate_bytes.len() > MAX_TRANSPORT_BYTES {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let canonical = encode_slate(&decode_slate(slate_bytes)?)?;
    if canonical != slate_bytes {
        return Err(ProtocolAdapterError::InvalidCanonicalEncoding);
    }
    let network = canonical_network(network)?;
    let mut body = Vec::with_capacity(slate_bytes.len().saturating_add(96));
    body.push(1);
    body.push(u8::from(response));
    body.push(u8::try_from(network.len()).map_err(|_| ProtocolAdapterError::InvalidTransport)?);
    body.extend_from_slice(network.as_bytes());
    body.extend_from_slice(&chain_id);
    body.extend_from_slice(slate_id.as_bytes());
    let length =
        u32::try_from(slate_bytes.len()).map_err(|_| ProtocolAdapterError::InvalidTransport)?;
    body.extend_from_slice(&length.to_le_bytes());
    body.extend_from_slice(slate_bytes);
    let hash = *dom_crypto::blake2b_256(&body).as_bytes();
    body.extend_from_slice(&hash);
    Ok(format!(
        "{TRANSPORT_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(body)
    ))
}

pub fn import_transport(text: &str) -> Result<TransportEnvelope, ProtocolAdapterError> {
    if text.len() > MAX_TRANSPORT_BYTES.saturating_mul(2).saturating_add(128)
        || !text.is_ascii()
        || text.bytes().any(|byte| byte.is_ascii_whitespace())
        || !text.starts_with(TRANSPORT_PREFIX)
    {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let encoded = text
        .strip_prefix(TRANSPORT_PREFIX)
        .ok_or(ProtocolAdapterError::InvalidTransport)?;
    if encoded.is_empty() || encoded.contains('=') {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolAdapterError::InvalidTransport)?;
    if bytes.len() < 1 + 1 + 1 + 32 + 16 + 4 + 32 {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let (without_hash, supplied_hash) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(ProtocolAdapterError::InvalidTransport)?,
    );
    if *dom_crypto::blake2b_256(without_hash).as_bytes() != supplied_hash {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let mut offset = 0usize;
    let version = take_u8(without_hash, &mut offset)?;
    if version != 1 {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let response = match take_u8(without_hash, &mut offset)? {
        0 => false,
        1 => true,
        _ => return Err(ProtocolAdapterError::InvalidTransport),
    };
    let network_len = usize::from(take_u8(without_hash, &mut offset)?);
    let network_bytes = take(without_hash, &mut offset, network_len)?;
    let network =
        std::str::from_utf8(network_bytes).map_err(|_| ProtocolAdapterError::InvalidTransport)?;
    let network = canonical_network(network)?;
    let chain_id = take_array::<32>(without_hash, &mut offset)?;
    let slate_id = Uuid::from_bytes(take_array::<16>(without_hash, &mut offset)?);
    let payload_len = usize::try_from(u32::from_le_bytes(take_array::<4>(
        without_hash,
        &mut offset,
    )?))
    .map_err(|_| ProtocolAdapterError::InvalidTransport)?;
    if payload_len > MAX_TRANSPORT_BYTES {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let payload = take(without_hash, &mut offset, payload_len)?.to_vec();
    if offset != without_hash.len() || encode_slate(&decode_slate(&payload)?)? != payload {
        return Err(ProtocolAdapterError::InvalidCanonicalEncoding);
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(supplied_hash);
    Ok(TransportEnvelope {
        version,
        response,
        network: network.to_owned(),
        chain_id,
        slate_id,
        payload,
        content_hash,
    })
}

pub fn qr_encode_transport(text: &str) -> Result<QrEncoding, ProtocolAdapterError> {
    let envelope = import_transport(text)?;
    if text.len() <= MAX_QR_SINGLE_TEXT_BYTES {
        return Ok(QrEncoding::Single {
            text: text.to_owned(),
            content_hash: envelope.content_hash,
        });
    }
    let message_id = envelope.content_hash;
    let total = text.len().div_ceil(QR_FRAME_PAYLOAD_BYTES);
    if total == 0 || total > MAX_QR_FRAMES {
        return Err(ProtocolAdapterError::InvalidQrFrame);
    }
    let total_u16 = u16::try_from(total).map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    let frames = text
        .as_bytes()
        .chunks(QR_FRAME_PAYLOAD_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let index = u16::try_from(index).map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
            let mut integrity = Vec::with_capacity(32 + 2 + 2 + chunk.len());
            integrity.extend_from_slice(&message_id);
            integrity.extend_from_slice(&index.to_le_bytes());
            integrity.extend_from_slice(&total_u16.to_le_bytes());
            integrity.extend_from_slice(chunk);
            let checksum = dom_crypto::blake2b_256(&integrity);
            Ok(format!(
                "{QR_FRAME_PREFIX}{}.{}.{}.{}.{}",
                hex::encode(message_id),
                index,
                total_u16,
                URL_SAFE_NO_PAD.encode(chunk),
                hex::encode(checksum.as_bytes())
            ))
        })
        .collect::<Result<Vec<_>, ProtocolAdapterError>>()?;
    Ok(QrEncoding::Multi {
        frames,
        content_hash: message_id,
    })
}

impl QrReassembler {
    pub fn status(&self) -> QrReassemblyStatus {
        QrReassemblyStatus {
            message_id: self.message_id,
            received_frames: u16::try_from(self.frames.len()).unwrap_or(u16::MAX),
            total_frames: self.total_frames.unwrap_or(0),
            complete_text: None,
        }
    }

    pub fn push(&mut self, scanned: &str) -> Result<QrReassemblyStatus, ProtocolAdapterError> {
        if scanned.starts_with(TRANSPORT_PREFIX) {
            if self.message_id.is_some() {
                return Err(ProtocolAdapterError::InvalidQrFrame);
            }
            let envelope = import_transport(scanned)?;
            return Ok(QrReassemblyStatus {
                message_id: Some(envelope.content_hash),
                received_frames: 1,
                total_frames: 1,
                complete_text: Some(scanned.to_owned()),
            });
        }
        let frame = parse_qr_frame(scanned)?;
        match (self.message_id, self.total_frames) {
            (None, None) => {
                self.message_id = Some(frame.message_id);
                self.total_frames = Some(frame.total);
            }
            (Some(message_id), Some(total))
                if message_id == frame.message_id && total == frame.total => {}
            _ => return Err(ProtocolAdapterError::InvalidQrFrame),
        }
        if let Some(existing) = self.frames.get(&frame.index) {
            if existing != &frame.payload {
                return Err(ProtocolAdapterError::InvalidQrFrame);
            }
        } else {
            self.frames.insert(frame.index, frame.payload);
        }
        let total = self
            .total_frames
            .ok_or(ProtocolAdapterError::InvalidQrFrame)?;
        if self.frames.len() > usize::from(total) {
            return Err(ProtocolAdapterError::InvalidQrFrame);
        }
        let complete_text = if self.frames.len() == usize::from(total) {
            let mut bytes = Vec::new();
            for index in 0..total {
                bytes.extend_from_slice(
                    self.frames
                        .get(&index)
                        .ok_or(ProtocolAdapterError::InvalidQrFrame)?,
                );
            }
            if bytes.len() > MAX_TRANSPORT_BYTES.saturating_mul(2).saturating_add(128) {
                return Err(ProtocolAdapterError::InvalidQrFrame);
            }
            let text =
                String::from_utf8(bytes).map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
            let envelope = import_transport(&text)?;
            if Some(envelope.content_hash) != self.message_id {
                return Err(ProtocolAdapterError::InvalidQrFrame);
            }
            Some(text)
        } else {
            None
        };
        Ok(QrReassemblyStatus {
            message_id: self.message_id,
            received_frames: u16::try_from(self.frames.len())
                .map_err(|_| ProtocolAdapterError::InvalidQrFrame)?,
            total_frames: total,
            complete_text,
        })
    }

    pub fn clear(&mut self) {
        self.message_id = None;
        self.total_frames = None;
        self.frames.clear();
    }
}

struct ParsedQrFrame {
    message_id: [u8; 32],
    index: u16,
    total: u16,
    payload: Vec<u8>,
}

fn parse_qr_frame(value: &str) -> Result<ParsedQrFrame, ProtocolAdapterError> {
    if value.len() > QR_FRAME_PAYLOAD_BYTES.saturating_mul(2).saturating_add(256)
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ProtocolAdapterError::InvalidQrFrame);
    }
    let mut fields = value.split('.');
    if fields.next() != Some("DOMQR1") {
        return Err(ProtocolAdapterError::InvalidQrFrame);
    }
    let id_hex = fields.next().ok_or(ProtocolAdapterError::InvalidQrFrame)?;
    let index = fields
        .next()
        .ok_or(ProtocolAdapterError::InvalidQrFrame)?
        .parse::<u16>()
        .map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    let total = fields
        .next()
        .ok_or(ProtocolAdapterError::InvalidQrFrame)?
        .parse::<u16>()
        .map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    let encoded = fields.next().ok_or(ProtocolAdapterError::InvalidQrFrame)?;
    let checksum_hex = fields.next().ok_or(ProtocolAdapterError::InvalidQrFrame)?;
    if fields.next().is_some()
        || total == 0
        || usize::from(total) > MAX_QR_FRAMES
        || index >= total
        || id_hex.len() != 64
        || checksum_hex.len() != 64
        || !id_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !checksum_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || encoded.contains('=')
    {
        return Err(ProtocolAdapterError::InvalidQrFrame);
    }
    let id = hex::decode(id_hex).map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    let checksum = hex::decode(checksum_hex).map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    let message_id: [u8; 32] = id
        .try_into()
        .map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProtocolAdapterError::InvalidQrFrame)?;
    if payload.len() > QR_FRAME_PAYLOAD_BYTES {
        return Err(ProtocolAdapterError::InvalidQrFrame);
    }
    let mut integrity = Vec::with_capacity(32 + 2 + 2 + payload.len());
    integrity.extend_from_slice(&message_id);
    integrity.extend_from_slice(&index.to_le_bytes());
    integrity.extend_from_slice(&total.to_le_bytes());
    integrity.extend_from_slice(&payload);
    if *dom_crypto::blake2b_256(&integrity).as_bytes() != checksum.as_slice() {
        return Err(ProtocolAdapterError::InvalidQrFrame);
    }
    Ok(ParsedQrFrame {
        message_id,
        index,
        total,
        payload,
    })
}

fn canonical_network(value: &str) -> Result<&str, ProtocolAdapterError> {
    match value {
        "PRIVATE_TESTNET" | "PUBLIC_TESTNET" | "MAINNET" => Ok(value),
        _ => Err(ProtocolAdapterError::InvalidTransport),
    }
}
fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ProtocolAdapterError> {
    let end = offset
        .checked_add(length)
        .ok_or(ProtocolAdapterError::InvalidTransport)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(ProtocolAdapterError::InvalidTransport)?;
    *offset = end;
    Ok(value)
}
fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, ProtocolAdapterError> {
    Ok(take(bytes, offset, 1)?[0])
}
fn take_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], ProtocolAdapterError> {
    take(bytes, offset, N)?
        .try_into()
        .map_err(|_| ProtocolAdapterError::InvalidTransport)
}

fn encode_slate(slate: &Slate) -> Result<Vec<u8>, ProtocolAdapterError> {
    let mut writer = Writer::new();
    slate
        .serialize(&mut writer)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(writer.finish())
}
fn decode_slate(bytes: &[u8]) -> Result<Slate, ProtocolAdapterError> {
    if bytes.len() > MAX_TRANSPORT_BYTES {
        return Err(ProtocolAdapterError::InvalidCanonicalEncoding);
    }
    let mut reader = Reader::new(bytes);
    let slate = Slate::deserialize(&mut reader)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    reader
        .finish()
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(slate)
}
fn encode_transaction(
    tx: &dom_consensus::transaction::Transaction,
) -> Result<Vec<u8>, ProtocolAdapterError> {
    let mut writer = Writer::new();
    tx.serialize(&mut writer)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(writer.finish())
}
fn decode_transaction(
    bytes: &[u8],
) -> Result<dom_consensus::transaction::Transaction, ProtocolAdapterError> {
    let mut reader = Reader::new(bytes);
    let tx = dom_consensus::transaction::Transaction::deserialize(&mut reader)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    reader
        .finish()
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(tx)
}
fn validate_transaction(
    tx: &dom_consensus::transaction::Transaction,
) -> Result<(), ProtocolAdapterError> {
    validate_transaction_structure(tx).map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    validate_balance_equation(tx).map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    for output in &tx.outputs {
        if !bp2_verify(output.commitment.as_bytes(), &output.proof)
            .map_err(|_| ProtocolAdapterError::ProtocolRejected)?
        {
            return Err(ProtocolAdapterError::ProtocolRejected);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::{bp2_prove, BlindingFactor};

    #[test]
    fn authoritative_round_trip_is_canonical() {
        let blind = BlindingFactor::from_bytes([7; 32]).unwrap();
        let (_, commitment) = bp2_prove(500_000, &blind).unwrap();
        let sender = build_sender(
            &[InputMaterial {
                commitment,
                blinding: [7; 32],
                value: 500_000,
            }],
            400_000,
            50_000,
            [9; 32],
            None,
            None,
        )
        .unwrap();
        let response = create_recipient_response(&sender.slate_bytes, [9; 32]).unwrap();
        let finalized = finalize_sender(
            &response.slate_bytes,
            &sender.slate_bytes,
            &sender.secrets,
            [9; 32],
        )
        .unwrap();
        assert_eq!(
            validate_finalized_bytes(&finalized.bytes)
                .unwrap()
                .kernel_excess,
            finalized.kernel_excess
        );
        let text = export_transport(
            "PRIVATE_TESTNET",
            [9; 32],
            Uuid::nil(),
            false,
            &sender.slate_bytes,
        )
        .unwrap();
        assert_eq!(import_transport(&text).unwrap().payload, sender.slate_bytes);
        let qr = qr_encode_transport(&text).unwrap();
        let frames = match qr {
            QrEncoding::Single { text, .. } => vec![text],
            QrEncoding::Multi { frames, .. } => frames,
        };
        let mut reassembler = QrReassembler::default();
        let mut completed = None;
        for frame in frames.iter().rev() {
            completed = reassembler.push(frame).unwrap().complete_text.or(completed);
        }
        assert_eq!(completed.unwrap(), text);
    }

    #[test]
    fn height_locked_sender_plumbs_feature_and_height_to_final_transaction() {
        let blind = BlindingFactor::from_bytes([8; 32]).unwrap();
        let (_, commitment) = bp2_prove(500_000, &blind).unwrap();
        let sender = build_sender(
            &[InputMaterial {
                commitment,
                blinding: [8; 32],
                value: 500_000,
            }],
            400_000,
            50_000,
            [9; 32],
            Some(dom_core::KERNEL_FEAT_HEIGHT_LOCKED),
            Some(4242),
        )
        .unwrap();
        assert_eq!(decode_slate(&sender.slate_bytes).unwrap().lock_height, 4242);

        let response = create_recipient_response(&sender.slate_bytes, [9; 32]).unwrap();
        let finalized = finalize_sender(
            &response.slate_bytes,
            &sender.slate_bytes,
            &sender.secrets,
            [9; 32],
        )
        .unwrap();
        let tx = decode_transaction(&finalized.bytes).unwrap();
        assert_eq!(tx.kernels[0].features, dom_core::KERNEL_FEAT_HEIGHT_LOCKED);
        assert_eq!(tx.kernels[0].lock_height, 4242);
    }

    #[test]
    fn kernel_options_fail_closed_on_inconsistent_pairs() {
        assert_eq!(
            resolve_kernel_lock(Some(dom_core::KERNEL_FEAT_PLAIN), Some(1))
                .unwrap_err()
                .to_string(),
            ProtocolAdapterError::InvalidKernelConfiguration.to_string()
        );
        assert_eq!(
            resolve_kernel_lock(Some(dom_core::KERNEL_FEAT_HEIGHT_LOCKED), None)
                .unwrap_err()
                .to_string(),
            ProtocolAdapterError::InvalidKernelConfiguration.to_string()
        );
    }

    #[test]
    fn transport_rejects_noncanonical_and_wrong_role_data() {
        assert!(import_transport("DOMSLATE1.bad").is_err());
        assert!(import_transport("DOMSLATE1. bad").is_err());
        assert!(QrReassembler::default().push("DOMQR1.bad").is_err());
    }
}
