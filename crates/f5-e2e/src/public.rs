//! Operational Regtest V2 evidence composition for the Annex M F5 harness.
//!
//! The checkpoint and policy are supplied exclusively by an independently
//! pinned owner-only authority. The untrusted evidence document can carry only
//! a continuation after that checkpoint; it cannot nominate a trust root.

use adapter_dom_sim::{LockState, SimChain, SimTx, SubmitResult};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{block::Header, Block, Transaction};
use btc_evidence::{
    verified_v2_outcome_to_uspe_event, verify_evidence_v2, BitcoinEvidenceNetworkV2,
    BitcoinEvidenceRouteBindingV2, BitcoinHeaderPolicyBindingV2, BitcoinOutPointV2,
    BitcoinOutcomeV2, BitcoinTransactionClaimV2, KeystoneBitcoinEvidenceV2, RegtestHeaderPolicyV2,
};
use btc_observer::{
    ApplyOutcome, BitcoinChainCursorV1, BitcoinNetworkV1 as ObserverNetwork,
    BitcoinObservedEventV1, ObserverStore,
};
use serde::Deserialize;
use uspe::{assurance_transition, AssuranceContext, AssuranceState};

use crate::regtest_authority::PinnedRegtestHeaderAuthorityV2;
use crate::{
    decode_hex_internal, verify_claim_witness, verify_refund_witness, FundingRef, ADAPTOR_T,
};

const REGTEST_EVIDENCE_SCHEMA_V2: &str = "dom-f5-regtest-evidence-v2";
const REGTEST_NETWORK_KIND_V2: &str = "bitcoin-regtest-v2";
const MAX_REGTEST_EVIDENCE_INPUT_BYTES_V2: u64 = 32 * 1024 * 1024;

/// Expected terminal path supplied from the frozen F5 route, not from the
/// untrusted evidence file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegtestExpectedOutcomeV2 {
    /// Cooperative key-path claim.
    Claim,
    /// CSV script-path refund.
    Refund,
}

/// Frozen route identity supplied by its owner, never by Bitcoin evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegtestRouteExpectationV2 {
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
}

impl RegtestRouteExpectationV2 {
    /// Creates a non-null route identity.
    pub fn new(settlement_id: [u8; 32], terms_hash: [u8; 32]) -> Result<Self, String> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err("invalid frozen Regtest route expectation".to_string());
        }
        Ok(Self {
            settlement_id,
            terms_hash,
        })
    }
}

/// Frozen public bindings against which one Regtest V2 evidence file is
/// checked. Confirmation depth belongs to the separately pinned authority.
pub struct RegtestEvidenceExpectationV2 {
    route: RegtestRouteExpectationV2,
    funding: FundingRef,
    destination_spk: Vec<u8>,
    fee_sat: u64,
    outcome: RegtestExpectedOutcomeV2,
}

impl RegtestEvidenceExpectationV2 {
    /// Creates a route-owned expectation for the untrusted Regtest evidence.
    pub fn new(
        route: RegtestRouteExpectationV2,
        funding: FundingRef,
        destination_spk: Vec<u8>,
        fee_sat: u64,
        outcome: RegtestExpectedOutcomeV2,
    ) -> Result<Self, String> {
        if funding.txid == [0; 32]
            || funding.amount_sat <= fee_sat
            || destination_spk.is_empty()
            || destination_spk.len() > 10_000
        {
            return Err("invalid frozen Regtest evidence expectation".to_string());
        }
        Ok(Self {
            route,
            funding,
            destination_spk,
            fee_sat,
            outcome,
        })
    }
}

/// Public results emitted by the Regtest V2 evidence/USPE pass.
pub struct PublicEvidenceResult {
    /// Spending transaction id in RPC display order.
    pub txid: String,
    /// Witness transaction id in RPC display order.
    pub wtxid: String,
    /// Containing block hash in RPC display order.
    pub block_hash: String,
    /// Confirmation depth, including the containing block as depth one.
    pub confirmation_depth: u32,
    /// Exact transaction count authenticated from the complete block.
    pub total_transactions: u32,
    /// Exact zero-based position authenticated in the complete block.
    pub transaction_position: u32,
    /// Canonical digest of the V2 evidence authenticated by the authority.
    pub evidence_digest: [u8; 32],
    /// Digest of the genesis-rooted header authority result.
    pub header_authority_digest: [u8; 32],
    /// USPE state after consuming the verified V2 outcome event.
    pub uspe_state: &'static str,
    /// Claim and refund remained mutually exclusive in dom-sim.
    pub economic_terminal_unique: bool,
    /// The durable observer deduplicated redelivery.
    pub observer_redelivery_idempotent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegtestEvidenceInputV2 {
    schema: String,
    network_kind: String,
    network_genesis: String,
    settlement_id: String,
    terms_hash: String,
    expected_outpoint: RegtestOutpointInputV2,
    outcome: String,
    block_height: u64,
    block_hash: String,
    block_hex: String,
    transaction_position: u32,
    txid: String,
    wtxid: String,
    minimum_confirmation_depth: u32,
    continuation_headers: Vec<RegtestHeaderInputV2>,
    confirmation_headers: Vec<RegtestHeaderInputV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegtestOutpointInputV2 {
    txid: String,
    vout: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegtestHeaderInputV2 {
    height: u64,
    hash: String,
    header: String,
}

/// Verifies a complete local Regtest evidence V2 input.
///
/// The input must contain a canonical full block, the continuation after the
/// externally pinned checkpoint through the containing block, and all
/// confirmation successors. The function never decodes or falls back to
/// evidence V1.
pub fn verify_regtest_evidence_file(
    path: &std::path::Path,
    expectation: &RegtestEvidenceExpectationV2,
    pinned_authority: &PinnedRegtestHeaderAuthorityV2,
    observer_state_directory: &std::path::Path,
) -> Result<PublicEvidenceResult, String> {
    let metadata = std::fs::metadata(path).map_err(|error| format!("evidence input: {error}"))?;
    if metadata.len() == 0 || metadata.len() > MAX_REGTEST_EVIDENCE_INPUT_BYTES_V2 {
        return Err("Regtest V2 evidence input exceeds its exact file bound".to_string());
    }
    let bytes = std::fs::read(path).map_err(|error| format!("evidence input: {error}"))?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).map_err(|_| "evidence input length overflow".to_string())?
            > MAX_REGTEST_EVIDENCE_INPUT_BYTES_V2
    {
        return Err("Regtest V2 evidence input exceeds its exact file bound".to_string());
    }
    let input: RegtestEvidenceInputV2 =
        serde_json::from_slice(&bytes).map_err(|error| format!("evidence json: {error}"))?;
    verify_regtest_evidence_input_v2(
        input,
        expectation,
        pinned_authority,
        observer_state_directory,
    )
}

fn verify_regtest_evidence_input_v2(
    input: RegtestEvidenceInputV2,
    expectation: &RegtestEvidenceExpectationV2,
    pinned_authority: &PinnedRegtestHeaderAuthorityV2,
    observer_state_directory: &std::path::Path,
) -> Result<PublicEvidenceResult, String> {
    if input.schema != REGTEST_EVIDENCE_SCHEMA_V2 || input.network_kind != REGTEST_NETWORK_KIND_V2 {
        return Err("evidence is not the exact F5 Regtest V2 schema".to_string());
    }

    let supplied_genesis = parse_display_hash(&input.network_genesis, "network genesis")?;
    let settlement = parse_internal_hash(&input.settlement_id, "settlement id")?;
    let terms = parse_internal_hash(&input.terms_hash, "terms hash")?;
    let expected_txid = parse_display_hash(&input.expected_outpoint.txid, "outpoint txid")?;
    let expected_outpoint = BitcoinOutPointV2::new(expected_txid, input.expected_outpoint.vout)
        .map_err(|error| error.to_string())?;
    let expected_block_hash = parse_display_hash(&input.block_hash, "block hash")?;
    let expected_txid_claim = parse_display_hash(&input.txid, "transaction id")?;
    let expected_wtxid = parse_display_hash(&input.wtxid, "witness transaction id")?;
    let outcome = match input.outcome.as_str() {
        "claim" => BitcoinOutcomeV2::KeyPathClaim,
        "refund" => BitcoinOutcomeV2::CsvScriptPathRefund,
        _ => return Err("outcome must be claim or refund".to_string()),
    };
    let expected_outcome = match expectation.outcome {
        RegtestExpectedOutcomeV2::Claim => BitcoinOutcomeV2::KeyPathClaim,
        RegtestExpectedOutcomeV2::Refund => BitcoinOutcomeV2::CsvScriptPathRefund,
    };
    let authority_facts = pinned_authority.facts();
    if settlement != expectation.route.settlement_id
        || terms != expectation.route.terms_hash
        || expected_txid != expectation.funding.txid
        || input.expected_outpoint.vout != expectation.funding.vout
        || input.minimum_confirmation_depth != authority_facts.minimum_confirmation_depth
        || outcome != expected_outcome
    {
        return Err("Regtest evidence diverges from the frozen route expectation".to_string());
    }

    let continuation_start = authority_facts
        .checkpoint_height
        .checked_add(1)
        .ok_or_else(|| "Regtest continuation height overflow".to_string())?;
    let continuation_headers = decode_header_range_v2(
        &input.continuation_headers,
        continuation_start,
        RegtestHeaderPolicyV2::MAX_CONTINUATION_HEADERS,
        "continuation",
    )?;
    let continuation_count = u64::try_from(continuation_headers.len())
        .map_err(|_| "Regtest continuation length overflow".to_string())?;
    let derived_block_height = authority_facts
        .checkpoint_height
        .checked_add(continuation_count)
        .ok_or_else(|| "Regtest containing height overflow".to_string())?;
    if derived_block_height != input.block_height {
        return Err("Regtest containing height does not match checkpoint continuation".to_string());
    }
    let confirmation_start = input
        .block_height
        .checked_add(1)
        .ok_or_else(|| "Regtest confirmation height overflow".to_string())?;
    let confirmation_headers = decode_header_range_v2(
        &input.confirmation_headers,
        confirmation_start,
        KeystoneBitcoinEvidenceV2::MAX_CONFIRMATION_HEADERS as usize,
        "confirmation",
    )?;

    let full_block = decode_lower_hex(&input.block_hex, "full block")?;
    if full_block.is_empty()
        || full_block.len() > KeystoneBitcoinEvidenceV2::MAX_FULL_BLOCK_BYTES as usize
    {
        return Err("Regtest V2 full block exceeds its hard bound".to_string());
    }
    let block: Block = deserialize(&full_block).map_err(|error| format!("full block: {error}"))?;
    if serialize(&block) != full_block {
        return Err("Regtest V2 full block is not canonically encoded".to_string());
    }
    if block.block_hash().to_raw_hash().to_byte_array() != expected_block_hash {
        return Err("full block hash does not match the explicit Regtest binding".to_string());
    }
    let containing_header: [u8; 80] = serialize(&block.header)
        .try_into()
        .map_err(|_| "containing header is not exactly 80 bytes".to_string())?;
    match continuation_headers.last() {
        Some(terminal_header) if terminal_header != &containing_header => {
            return Err("full block is not the terminal Regtest continuation header".to_string());
        }
        None if block.block_hash().to_raw_hash().to_byte_array()
            != authority_facts.checkpoint_block_hash =>
        {
            return Err("full block does not match the pinned Regtest checkpoint".to_string());
        }
        _ => {}
    }

    let position = usize::try_from(input.transaction_position)
        .map_err(|_| "transaction position overflow".to_string())?;
    let transaction: &Transaction = block
        .txdata
        .get(position)
        .ok_or_else(|| "transaction position is outside the complete block".to_string())?;
    if transaction.compute_txid().to_raw_hash().to_byte_array() != expected_txid_claim
        || transaction.compute_wtxid().to_raw_hash().to_byte_array() != expected_wtxid
    {
        return Err("transaction id or witness id does not match the complete block".to_string());
    }

    let header_policy = BitcoinHeaderPolicyBindingV2::new(
        BitcoinEvidenceNetworkV2::Regtest,
        supplied_genesis,
        input.block_height,
        authority_facts.policy_digest,
        authority_facts.checkpoint_digest,
        input.minimum_confirmation_depth,
    )
    .map_err(|error| error.to_string())?;
    let total_transactions = u32::try_from(block.txdata.len())
        .map_err(|_| "complete block transaction count overflow".to_string())?;
    let transaction_claim = BitcoinTransactionClaimV2::new(
        expected_txid_claim,
        expected_wtxid,
        expected_outpoint,
        total_transactions,
        input.transaction_position,
        outcome,
    )
    .map_err(|error| error.to_string())?;
    let evidence = KeystoneBitcoinEvidenceV2::new(
        BitcoinEvidenceRouteBindingV2::new(settlement, terms).map_err(|error| error.to_string())?,
        header_policy,
        transaction_claim,
        full_block,
        confirmation_headers,
    )
    .map_err(|error| error.to_string())?;

    // Force the consumer through the distinct V2 wire codec. There is no
    // magic/version fallback to V1 at this boundary.
    let encoded = evidence.encode().map_err(|error| error.to_string())?;
    let evidence = KeystoneBitcoinEvidenceV2::decode(&encoded)
        .map_err(|error| format!("canonical V2 evidence round-trip: {error}"))?;
    let authenticated = pinned_authority
        .authority()
        .authenticate(&evidence, &continuation_headers)
        .map_err(|error| error.to_string())?;
    let verified =
        verify_evidence_v2(&evidence, &authenticated).map_err(|error| error.to_string())?;

    let transaction_bytes = serialize(transaction);
    let signature_ok = match outcome {
        BitcoinOutcomeV2::KeyPathClaim => verify_claim_witness(
            &transaction_bytes,
            &expectation.funding,
            &expectation.destination_spk,
            expectation.fee_sat,
        ),
        BitcoinOutcomeV2::CsvScriptPathRefund => verify_refund_witness(
            &transaction_bytes,
            &expectation.funding,
            &expectation.destination_spk,
            expectation.fee_sat,
        ),
    };
    if !signature_ok {
        return Err("independent Regtest BIP340/template verification failed".to_string());
    }

    let observer_path = secure_observer_database_path_v2(observer_state_directory, settlement)?;
    let mut observer = ObserverStore::open(&observer_path).map_err(|error| error.to_string())?;
    let observer_genesis =
        BitcoinChainCursorV1::genesis(ObserverNetwork::Regtest, supplied_genesis);
    observer
        .init_cursor(&observer_genesis)
        .map_err(|error| error.to_string())?;
    if !observer
        .evidence_is_valid(&verified.txid())
        .map_err(|error| error.to_string())?
    {
        let seen = match outcome {
            BitcoinOutcomeV2::KeyPathClaim => BitcoinObservedEventV1::ClaimWitnessSeen {
                txid: verified.txid(),
                wtxid: verified.wtxid(),
            },
            BitcoinOutcomeV2::CsvScriptPathRefund => BitcoinObservedEventV1::RefundSeen {
                txid: verified.txid(),
                wtxid: verified.wtxid(),
            },
        };
        let first_apply = observer
            .apply_event(
                &observer_genesis,
                &seen,
                verified.block_hash(),
                verified.block_height(),
                verified.block_hash(),
            )
            .map_err(|error| error.to_string())?;
        let duplicate_apply = observer
            .apply_event(
                &observer_genesis,
                &seen,
                verified.block_hash(),
                verified.block_height(),
                verified.block_hash(),
            )
            .map_err(|error| error.to_string())?;
        if first_apply != ApplyOutcome::Applied || duplicate_apply != ApplyOutcome::Duplicate {
            return Err("observer did not durably deduplicate V2 evidence".to_string());
        }

        let confirmed = match outcome {
            BitcoinOutcomeV2::KeyPathClaim => BitcoinObservedEventV1::ClaimConfirmed {
                evidence_ref: verified.txid(),
                height: verified.block_height(),
            },
            BitcoinOutcomeV2::CsvScriptPathRefund => BitcoinObservedEventV1::RefundConfirmed {
                evidence_ref: verified.txid(),
                height: verified.block_height(),
            },
        };
        let current_cursor = observer
            .cursor(ObserverNetwork::Regtest)
            .map_err(|error| error.to_string())?;
        observer
            .apply_event(
                &current_cursor,
                &confirmed,
                authenticated.confirmation_tip_hash(),
                authenticated.confirmation_tip_height(),
                authenticated.confirmation_tip_hash(),
            )
            .map_err(|error| error.to_string())?;
    }
    if !observer
        .evidence_is_valid(&verified.txid())
        .map_err(|error| error.to_string())?
    {
        return Err("observer did not retain the authenticated V2 evidence reference".to_string());
    }

    if !dom_sim_consumes(outcome, settlement) {
        return Err("dom-sim did not preserve exactly one economic terminal".to_string());
    }
    let event = verified_v2_outcome_to_uspe_event(&verified);
    let context = AssuranceContext {
        state: AssuranceState::ClaimWindow,
        terms_hash: terms,
        compensation_cap: 1,
    };
    let transition = assurance_transition(context, &event).map_err(|error| error.to_string())?;
    if transition.next.state != AssuranceState::EvidenceVerification {
        return Err("USPE did not consume the header-authenticated V2 outcome".to_string());
    }

    Ok(PublicEvidenceResult {
        txid: display_hash(&verified.txid()),
        wtxid: display_hash(&verified.wtxid()),
        block_hash: display_hash(&verified.block_hash()),
        confirmation_depth: verified.confirmation_depth(),
        total_transactions: verified.total_transactions(),
        transaction_position: verified.transaction_position(),
        evidence_digest: verified.evidence_digest(),
        header_authority_digest: verified.header_authority_digest(),
        uspe_state: "EvidenceVerification",
        economic_terminal_unique: true,
        observer_redelivery_idempotent: true,
    })
}

#[cfg(not(target_os = "linux"))]
fn secure_observer_database_path_v2(
    _state_directory: &std::path::Path,
    _settlement: [u8; 32],
) -> Result<std::path::PathBuf, String> {
    Err("Regtest V2 observer state requires Linux owner-only storage".to_string())
}

#[cfg(target_os = "linux")]
fn secure_observer_database_path_v2(
    state_directory: &std::path::Path,
    settlement: [u8; 32],
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let directory = std::fs::symlink_metadata(state_directory)
        .map_err(|_| "Regtest observer state directory is unavailable".to_string())?;
    if !state_directory.is_absolute()
        || std::fs::canonicalize(state_directory)
            .map_err(|_| "Regtest observer state directory is unavailable".to_string())?
            != state_directory
        || !directory.file_type().is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != rustix::process::geteuid().as_raw()
        || directory.mode() & 0o7777 != 0o700
        || directory.nlink() == 0
    {
        return Err("Regtest observer state directory is not exact owner-only storage".to_string());
    }
    let path = state_directory.join(format!(
        "{}-regtest-v2-observer.sqlite3",
        crate::hex_internal(&settlement)
    ));
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|_| "failed to create Regtest observer database".to_string())?;
            file.sync_all()
                .map_err(|_| "failed to persist Regtest observer database".to_string())?;
            std::fs::File::open(state_directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| "failed to persist Regtest observer state directory".to_string())?;
        }
        Ok(_) => {}
        Err(_) => return Err("Regtest observer database is unavailable".to_string()),
    }
    let file = std::fs::symlink_metadata(&path)
        .map_err(|_| "Regtest observer database is unavailable".to_string())?;
    if !file.file_type().is_file()
        || file.file_type().is_symlink()
        || file.uid() != rustix::process::geteuid().as_raw()
        || file.mode() & 0o7777 != 0o600
        || file.nlink() != 1
    {
        return Err("Regtest observer database is not an owner-only single-link file".to_string());
    }
    Ok(path)
}

fn decode_header_range_v2(
    entries: &[RegtestHeaderInputV2],
    starting_height: u64,
    maximum: usize,
    label: &str,
) -> Result<Vec<[u8; 80]>, String> {
    if entries.len() > maximum {
        return Err(format!("Regtest {label} headers exceed their hard bound"));
    }
    let mut headers = Vec::with_capacity(entries.len());
    for (offset, entry) in entries.iter().enumerate() {
        let offset =
            u64::try_from(offset).map_err(|_| format!("Regtest {label} offset overflow"))?;
        let expected_height = starting_height
            .checked_add(offset)
            .ok_or_else(|| format!("Regtest {label} height overflow"))?;
        if entry.height != expected_height {
            return Err(format!("Regtest {label} header heights are not contiguous"));
        }
        let raw: [u8; 80] = decode_lower_hex(&entry.header, "header")?
            .try_into()
            .map_err(|_| format!("Regtest {label} header is not exactly 80 bytes"))?;
        let header: Header =
            deserialize(&raw).map_err(|error| format!("Regtest header: {error}"))?;
        if serialize(&header) != raw {
            return Err(format!("Regtest {label} header is not canonically encoded"));
        }
        if header.block_hash().to_string() != entry.hash {
            return Err(format!("Regtest {label} header hash mismatch"));
        }
        headers.push(raw);
    }
    Ok(headers)
}

fn parse_internal_hash(value: &str, field: &str) -> Result<[u8; 32], String> {
    decode_lower_hex(value, field)?
        .try_into()
        .map_err(|_| format!("{field} must be exactly 32-byte lowercase hex"))
}

fn parse_display_hash(value: &str, field: &str) -> Result<[u8; 32], String> {
    let mut bytes = parse_internal_hash(value, field)?;
    bytes.reverse();
    Ok(bytes)
}

fn decode_lower_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(format!("{field} must be canonical lowercase hex"));
    }
    decode_hex_internal(value).ok_or_else(|| format!("{field} must be canonical lowercase hex"))
}

fn display_hash(bytes: &[u8; 32]) -> String {
    crate::hex_internal(&bytes.iter().rev().copied().collect::<Vec<_>>())
}

fn dom_sim_consumes(outcome: BitcoinOutcomeV2, settlement: [u8; 32]) -> bool {
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
        revealed: ADAPTOR_T,
    };
    let refund = SimTx::Refund {
        lock_id: settlement,
        not_before_height: 2,
    };
    let (terminal, conflicting_terminal) = match outcome {
        BitcoinOutcomeV2::KeyPathClaim => (claim, refund),
        BitcoinOutcomeV2::CsvScriptPathRefund => (refund, claim),
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::serialize;
    use bitcoin::Network;

    use super::{
        verify_regtest_evidence_file, RegtestEvidenceExpectationV2, RegtestExpectedOutcomeV2,
        RegtestRouteExpectationV2,
    };
    use crate::{FundingRef, PinnedRegtestHeaderAuthorityV2};

    #[test]
    fn regtest_v2_never_falls_back_to_legacy_or_unknown_json() {
        let directory =
            std::env::temp_dir().join(format!("dom-f5-regtest-v2-refusal-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create isolated test directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("set owner-only test mode");
        let path = directory.join("evidence.json");
        std::fs::write(
            &path,
            br#"{"network_kind":"custom-signet-bip325","codec_version":1}"#,
        )
        .expect("write legacy-shaped input");
        let expectation = RegtestEvidenceExpectationV2::new(
            RegtestRouteExpectationV2::new([1; 32], [2; 32]).expect("valid route"),
            FundingRef {
                txid: [3; 32],
                vout: 0,
                amount_sat: 10_000,
            },
            vec![0x51],
            100,
            RegtestExpectedOutcomeV2::Claim,
        )
        .expect("valid expectation");
        let ancestry = vec![serialize(&genesis_block(Network::Regtest).header)
            .try_into()
            .expect("fixed-width genesis")];
        let authority = PinnedRegtestHeaderAuthorityV2::create_from_ancestry(
            &directory.join("authority"),
            1,
            &ancestry,
        )
        .expect("pinned authority");
        let observer_state = directory.join("observer-state");
        std::fs::create_dir(&observer_state).expect("create observer state");
        std::fs::set_permissions(&observer_state, std::fs::Permissions::from_mode(0o700))
            .expect("set owner-only observer state mode");
        let error = verify_regtest_evidence_file(&path, &expectation, &authority, &observer_state)
            .err()
            .expect("legacy-shaped input must not fall back");
        assert!(error.contains("evidence json"));
        std::fs::remove_dir_all(&directory).expect("remove isolated test directory");
    }
}
