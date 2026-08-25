//! Signet evidence composition for the Annex M matrix.

use adapter_dom_sim::{LockState, SimChain, SimTx, SubmitResult};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{block::Header, Block, Transaction};
use btc_evidence::{
    verified_outcome_to_uspe_event, verify_evidence, BitcoinEvidenceNetworkV1, BitcoinOutPointV1,
    BitcoinOutcomeV1, BoundedMerkleBranchV1, KeystoneBitcoinEvidenceV1,
};
use btc_observer::{
    ApplyOutcome, BitcoinChainCursorV1, BitcoinNetworkV1 as ObserverNetwork,
    BitcoinObservedEventV1, ObserverStore,
};
use serde_json::Value;
use uspe::{assurance_transition, AssuranceContext, AssuranceState};

use crate::{
    decode_hex_internal, row_secret, verify_public_claim_witness, verify_public_refund_witness,
    FundingRef, PublicRow, ADAPTOR_T,
};

const SIGNET_GENESIS_INTERNAL: [u8; 32] = [
    0xf6, 0x1e, 0xee, 0x3b, 0x63, 0xa3, 0x80, 0xa4, 0x77, 0xa0, 0x63, 0xaf, 0x32, 0xb2, 0xbb, 0xc9,
    0x7c, 0x9f, 0xf9, 0xf0, 0x1f, 0x2c, 0x42, 0x25, 0xe9, 0x73, 0x98, 0x81, 0x08, 0x00, 0x00, 0x00,
];
const CUSTOM_SIGNET_CHALLENGE: &str =
    "21030f293b15c1014a5a747712be70543883a204e546fef03fea9ea6d939f6e9f4e0ac";
const CUSTOM_SIGNET_CHALLENGE_HASH: &str =
    "78b0e44ba256abd722c183910d98cbb91f2c50376d07788df3e187417a8e7e40";
const CUSTOM_SIGNET_MESSAGE_MAGIC: &str = "d7e27b1c";

/// Signet profile whose network identity is bound by the evidence caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignetEvidenceProfile {
    /// The operator-pinned BIP-325 custom Signet.
    Custom,
    /// Bitcoin's globally defined Public Signet (optional for F5).
    Public,
}

/// Public results emitted by the evidence/Keystone/USPE pass.
pub struct PublicEvidenceResult {
    /// Spending transaction id in RPC display order.
    pub txid: String,
    /// Witness transaction id in RPC display order.
    pub wtxid: String,
    /// Containing block hash in RPC display order.
    pub block_hash: String,
    /// Confirmation depth verified against linked headers.
    pub confirmation_depth: u32,
    /// USPE state after consuming the verified outcome event.
    pub uspe_state: &'static str,
    /// Claim and refund remained mutually exclusive in dom-sim.
    pub economic_terminal_unique: bool,
    /// The durable observer accepted the event once and deduplicated redelivery.
    pub observer_redelivery_idempotent: bool,
}

fn required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value[name]
        .as_str()
        .ok_or_else(|| format!("missing string field {name}"))
}

fn parse_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    decode_hex_internal(value)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{field} must be 32-byte hex"))
}

fn parse_rpc_txid(value: &str) -> Result<[u8; 32], String> {
    let mut bytes = parse_32(value, "outpoint txid")?;
    bytes.reverse();
    Ok(bytes)
}

fn display_hash(bytes: &[u8; 32]) -> String {
    crate::hex_internal(&bytes.iter().rev().copied().collect::<Vec<_>>())
}

fn branch_for(block: &Block, position: usize) -> BoundedMerkleBranchV1 {
    let mut hashes: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_raw_hash().to_byte_array())
        .collect();
    let mut at = position;
    let mut siblings = Vec::new();
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().expect("nonempty level"));
        }
        siblings.push(hashes[at ^ 1]);
        let mut next = Vec::with_capacity(hashes.len() / 2);
        for pair in hashes.chunks_exact(2) {
            let mut joined = [0u8; 64];
            joined[..32].copy_from_slice(&pair[0]);
            joined[32..].copy_from_slice(&pair[1]);
            next.push(sha256d::Hash::hash(&joined).to_byte_array());
        }
        at /= 2;
        hashes = next;
    }
    BoundedMerkleBranchV1 {
        siblings,
        position: position as u32,
    }
}

fn dom_sim_consumes(row: PublicRow, outcome: BitcoinOutcomeV1, settlement: [u8; 32]) -> bool {
    let mut chain = SimChain::new();
    if !matches!(
        chain.submit(SimTx::Lock {
            lock_id: settlement
        }),
        SubmitResult::Accepted { .. }
    ) {
        return false;
    }
    chain.advance(1);
    let claim = SimTx::Claim {
        lock_id: settlement,
        revealed: row_secret(ADAPTOR_T, Some(row)),
    };
    let refund = SimTx::Refund {
        lock_id: settlement,
        not_before_height: 2,
    };
    let (terminal, conflicting_terminal) = match outcome {
        BitcoinOutcomeV1::KeyPathClaim => (claim, refund),
        BitcoinOutcomeV1::CsvScriptPathRefund => (refund, claim),
    };
    if !matches!(chain.submit(terminal), SubmitResult::Accepted { .. }) {
        return false;
    }
    chain.advance(1);
    matches!(
        chain.submit(conflicting_terminal),
        SubmitResult::Rejected(_)
    ) && chain.lock_state(settlement) == LockState::Spent
}

/// Verifies a Core-returned Public-Signet full block.
pub fn verify_public_evidence_file(
    path: &std::path::Path,
    row: PublicRow,
) -> Result<PublicEvidenceResult, String> {
    verify_signet_evidence_file(path, row, SignetEvidenceProfile::Public)
}

/// Verifies a Core-returned custom-Signet full block.
pub fn verify_custom_evidence_file(
    path: &std::path::Path,
    row: PublicRow,
) -> Result<PublicEvidenceResult, String> {
    verify_signet_evidence_file(path, row, SignetEvidenceProfile::Custom)
}

fn verify_signet_evidence_file(
    path: &std::path::Path,
    row: PublicRow,
    profile: SignetEvidenceProfile,
) -> Result<PublicEvidenceResult, String> {
    let input: Value = serde_json::from_slice(
        &std::fs::read(path).map_err(|error| format!("evidence input: {error}"))?,
    )
    .map_err(|error| format!("evidence json: {error}"))?;
    let expected_kind = match profile {
        SignetEvidenceProfile::Custom => "custom-signet-bip325",
        SignetEvidenceProfile::Public => "bitcoin-public-signet",
    };
    if required_string(&input, "network_kind")? != expected_kind {
        return Err("evidence network kind does not match the selected verifier".to_string());
    }
    let mut supplied_genesis = parse_32(
        required_string(&input, "network_genesis")?,
        "network genesis",
    )?;
    supplied_genesis.reverse();
    if supplied_genesis != SIGNET_GENESIS_INTERNAL {
        return Err("evidence genesis does not match the frozen Signet genesis".to_string());
    }
    if profile == SignetEvidenceProfile::Custom
        && (required_string(&input, "network_challenge")? != CUSTOM_SIGNET_CHALLENGE
            || required_string(&input, "network_challenge_hash")? != CUSTOM_SIGNET_CHALLENGE_HASH
            || required_string(&input, "network_message_magic")? != CUSTOM_SIGNET_MESSAGE_MAGIC)
    {
        return Err("evidence does not match the frozen custom-Signet identity".to_string());
    }

    let block_raw = decode_hex_internal(required_string(&input, "block_hex")?)
        .ok_or("bad block hex".to_string())?;
    let block: Block = deserialize(&block_raw).map_err(|error| error.to_string())?;
    if !block.check_merkle_root() || !block.check_witness_commitment() {
        return Err("full block failed merkle-root or witness-commitment validation".to_string());
    }
    let wanted_txid = required_string(&input, "txid")?;
    let position = block
        .txdata
        .iter()
        .position(|tx| tx.compute_txid().to_string() == wanted_txid)
        .ok_or("transaction absent from full Core block".to_string())?;
    let tx: &Transaction = &block.txdata[position];
    let settlement = parse_32(required_string(&input, "settlement_id")?, "settlement id")?;
    let terms = parse_32(required_string(&input, "terms_hash")?, "terms hash")?;
    let expected_txid = parse_rpc_txid(required_string(&input["expected_outpoint"], "txid")?)?;
    let expected_vout = input["expected_outpoint"]["vout"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("bad outpoint vout".to_string())?;
    let outcome = match required_string(&input, "outcome")? {
        "claim" => BitcoinOutcomeV1::KeyPathClaim,
        "refund" => BitcoinOutcomeV1::CsvScriptPathRefund,
        _ => return Err("outcome must be claim or refund".to_string()),
    };
    let headers: Vec<[u8; 80]> = input["confirmation_headers"]
        .as_array()
        .ok_or("missing confirmation headers".to_string())?
        .iter()
        .map(|value| {
            required_string(value, "header")
                .and_then(|header| decode_hex_internal(header).ok_or("bad header hex".to_string()))
                .and_then(|bytes| {
                    bytes
                        .try_into()
                        .map_err(|_| "header is not 80 bytes".to_string())
                })
        })
        .collect::<Result<_, _>>()?;
    let minimum = input["minimum_confirmation_depth"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("missing minimum confirmation depth".to_string())?;
    if headers.len() < minimum as usize {
        return Err("linked header proof is below the accepted finality policy".to_string());
    }
    let network = match profile {
        SignetEvidenceProfile::Custom => BitcoinEvidenceNetworkV1::CustomSignet,
        SignetEvidenceProfile::Public => BitcoinEvidenceNetworkV1::PublicSignet,
    };
    let mut evidence = KeystoneBitcoinEvidenceV1 {
        codec_version: 1,
        network,
        network_genesis_hash: supplied_genesis,
        settlement_id: settlement,
        terms_hash: terms,
        expected_outpoint: BitcoinOutPointV1 {
            txid: expected_txid,
            vout: expected_vout,
        },
        raw_transaction: serialize(tx),
        txid: tx.compute_txid().to_raw_hash().to_byte_array(),
        wtxid: tx.compute_wtxid().to_raw_hash().to_byte_array(),
        block_header: serialize(&block.header)
            .try_into()
            .map_err(|_| "header serialization length".to_string())?,
        block_height: input["block_height"]
            .as_u64()
            .ok_or("missing block height".to_string())?,
        txid_merkle_branch: branch_for(&block, position),
        confirmation_headers: headers,
        outcome,
    };

    let observer_network = match profile {
        SignetEvidenceProfile::Custom => ObserverNetwork::CustomSignet,
        SignetEvidenceProfile::Public => ObserverNetwork::PublicSignet,
    };
    let observer_path = path.with_extension("observer.sqlite");
    let mut observer = ObserverStore::open(&observer_path).map_err(|error| error.to_string())?;
    let observer_genesis = BitcoinChainCursorV1::genesis(observer_network, supplied_genesis);
    observer
        .init_cursor(&observer_genesis)
        .map_err(|error| error.to_string())?;
    let seen = match outcome {
        BitcoinOutcomeV1::KeyPathClaim => BitcoinObservedEventV1::ClaimWitnessSeen {
            txid: evidence.txid,
            wtxid: evidence.wtxid,
        },
        BitcoinOutcomeV1::CsvScriptPathRefund => BitcoinObservedEventV1::RefundSeen {
            txid: evidence.txid,
            wtxid: evidence.wtxid,
        },
    };
    let observed_block_hash = block.block_hash().to_raw_hash().to_byte_array();
    let first_apply = observer
        .apply_event(
            &observer_genesis,
            &seen,
            observed_block_hash,
            evidence.block_height,
            observed_block_hash,
        )
        .map_err(|error| error.to_string())?;
    let duplicate_apply = observer
        .apply_event(
            &observer_genesis,
            &seen,
            observed_block_hash,
            evidence.block_height,
            observed_block_hash,
        )
        .map_err(|error| error.to_string())?;
    if first_apply != ApplyOutcome::Applied || duplicate_apply != ApplyOutcome::Duplicate {
        return Err("observer did not apply once and deduplicate redelivery".to_string());
    }
    let verified = verify_evidence(&evidence).map_err(|error| error.to_string())?;

    let confirmed = match outcome {
        BitcoinOutcomeV1::KeyPathClaim => BitcoinObservedEventV1::ClaimConfirmed {
            evidence_ref: verified.txid,
            height: verified.block_height,
        },
        BitcoinOutcomeV1::CsvScriptPathRefund => BitcoinObservedEventV1::RefundConfirmed {
            evidence_ref: verified.txid,
            height: verified.block_height,
        },
    };
    let current_cursor = observer
        .cursor(observer_network)
        .map_err(|error| error.to_string())?;
    let confirmation_tip: Header = deserialize(
        evidence
            .confirmation_headers
            .last()
            .ok_or("confirmation header proof is empty".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let confirmation_tip_hash = confirmation_tip.block_hash().to_raw_hash().to_byte_array();
    observer
        .apply_event(
            &current_cursor,
            &confirmed,
            confirmation_tip_hash,
            verified.block_height + evidence.confirmation_headers.len() as u64,
            confirmation_tip_hash,
        )
        .map_err(|error| error.to_string())?;
    if !observer
        .evidence_is_valid(&verified.txid)
        .map_err(|error| error.to_string())?
    {
        return Err("observer did not persist the verified evidence reference".to_string());
    }

    let funding = FundingRef {
        txid: expected_txid,
        vout: expected_vout,
        amount_sat: input["funding_amount_sat"]
            .as_u64()
            .ok_or("missing funding amount".to_string())?,
    };
    let destination = decode_hex_internal(required_string(&input, "destination_spk")?)
        .ok_or("bad destination spk".to_string())?;
    let fee = input["fee_sat"].as_u64().ok_or("missing fee".to_string())?;
    let signature_ok = match outcome {
        BitcoinOutcomeV1::KeyPathClaim => {
            verify_public_claim_witness(row, &evidence.raw_transaction, &funding, &destination, fee)
        }
        BitcoinOutcomeV1::CsvScriptPathRefund => verify_public_refund_witness(
            row,
            &evidence.raw_transaction,
            &funding,
            &destination,
            fee,
        ),
    };
    if !signature_ok {
        return Err("independent BIP340/template verification failed".to_string());
    }

    let original_outpoint = evidence.expected_outpoint;
    evidence.expected_outpoint.vout ^= u32::MAX;
    if verify_evidence(&evidence).is_ok() {
        return Err("E13 invalid outpoint evidence was accepted".to_string());
    }
    evidence.expected_outpoint = original_outpoint;
    let mut tampered_tx: Transaction =
        deserialize(&evidence.raw_transaction).map_err(|error| error.to_string())?;
    let mut tampered_witness = tampered_tx
        .input
        .first()
        .ok_or("transaction has no input".to_string())?
        .witness
        .to_vec();
    let signature_byte = tampered_witness
        .first_mut()
        .and_then(|item| item.first_mut())
        .ok_or("transaction has no witness signature".to_string())?;
    *signature_byte ^= 1;
    tampered_tx.input[0].witness = bitcoin::Witness::from_slice(&tampered_witness);
    evidence.raw_transaction = serialize(&tampered_tx);
    if verify_evidence(&evidence).is_ok() {
        return Err("E14 tampered witness was accepted".to_string());
    }

    if !dom_sim_consumes(row, outcome, settlement) {
        return Err("dom-sim did not preserve exactly one economic terminal".to_string());
    }
    let event = verified_outcome_to_uspe_event(&verified);
    let context = AssuranceContext {
        state: AssuranceState::ClaimWindow,
        terms_hash: terms,
        compensation_cap: 1,
    };
    let transition = assurance_transition(context, &event).map_err(|error| error.to_string())?;
    if transition.next.state != AssuranceState::EvidenceVerification {
        return Err("USPE did not consume the verified outcome".to_string());
    }
    Ok(PublicEvidenceResult {
        txid: display_hash(&verified.txid),
        wtxid: display_hash(&verified.wtxid),
        block_hash: display_hash(&verified.block_hash),
        confirmation_depth: verified.confirmation_depth,
        uspe_state: "EvidenceVerification",
        economic_terminal_unique: true,
        observer_redelivery_idempotent: true,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_32, SIGNET_GENESIS_INTERNAL};

    #[test]
    fn frozen_signet_genesis_matches_core_rpc_byte_order() {
        let mut supplied = parse_32(
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            "network genesis",
        )
        .expect("the frozen genesis is valid hex");
        supplied.reverse();
        assert_eq!(supplied, SIGNET_GENESIS_INTERNAL);
    }
}
