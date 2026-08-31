//! F5 consumer tests for the genesis-rooted Regtest evidence V2 authority.

#![cfg(target_os = "linux")]

use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::absolute::LockTime;
use bitcoin::block::Version as BlockVersion;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use f5_e2e::{
    build_signed_claim, build_signed_refund, verify_regtest_evidence_file, FundingRef,
    PinnedRegtestHeaderAuthorityV2, RegtestEvidenceExpectationV2, RegtestExpectedOutcomeV2,
    RegtestRouteExpectationV2,
};
use serde_json::{json, Value};

const MINIMUM_DEPTH: u32 = 2;
const FEE_SAT: u64 = 2_000;
const DESTINATION_SPK: [u8; 22] = [
    0x00, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];

static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RegtestInputFixtureV2 {
    directory: std::path::PathBuf,
    input: Value,
    funding: FundingRef,
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    outcome: RegtestExpectedOutcomeV2,
    authority: PinnedRegtestHeaderAuthorityV2,
    observer_state: std::path::PathBuf,
}

impl RegtestInputFixtureV2 {
    fn expectation(&self) -> RegtestEvidenceExpectationV2 {
        RegtestEvidenceExpectationV2::new(
            RegtestRouteExpectationV2::new(self.settlement_id, self.terms_hash)
                .expect("fixture route is valid"),
            self.funding,
            DESTINATION_SPK.to_vec(),
            FEE_SAT,
            self.outcome,
        )
        .expect("fixture expectation is valid")
    }

    fn write(&self, name: &str, input: &Value) -> std::path::PathBuf {
        let path = self.directory.join(name);
        std::fs::write(
            &path,
            serde_json::to_vec(input).expect("fixture JSON encodes"),
        )
        .expect("fixture JSON writes");
        path
    }
}

impl Drop for RegtestInputFixtureV2 {
    fn drop(&mut self) {
        if self.directory.starts_with(std::env::temp_dir()) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn raw_header(header: &bitcoin::block::Header) -> [u8; 80] {
    serialize(header)
        .try_into()
        .expect("Bitcoin header is exactly 80 bytes")
}

fn header_entry(height: u64, header: &bitcoin::block::Header) -> Value {
    json!({
        "height": height,
        "hash": header.block_hash().to_string(),
        "header": hex(&raw_header(header)),
    })
}

fn mine_header(header: &mut bitcoin::block::Header) {
    let target = header.target();
    while header.validate_pow(target).is_err() {
        header.nonce = header.nonce.checked_add(1).expect("easy Regtest target");
    }
}

fn merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = transactions
        .iter()
        .map(|transaction| transaction.compute_txid().to_raw_hash().to_byte_array())
        .collect();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&left);
            bytes[32..].copy_from_slice(&right);
            next.push(sha256d::Hash::hash(&bytes).to_byte_array());
        }
        level = next;
    }
    level[0]
}

fn with_coinbase_witness_commitment(mut transactions: Vec<Transaction>) -> Vec<Transaction> {
    let witness_reserved_value = [0u8; 32];
    let mut coinbase_witness = Witness::new();
    coinbase_witness.push(witness_reserved_value);
    let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment_script.extend_from_slice(&[0u8; 32]);
    transactions.insert(
        0,
        Transaction {
            version: TxVersion(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: coinbase_witness,
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commitment_script),
            }],
        },
    );

    let provisional = Block {
        header: bitcoin::block::Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: transactions,
    };
    let witness_root = provisional
        .witness_root()
        .expect("fixture has a witness root");
    let commitment =
        Block::compute_witness_commitment(&witness_root, witness_reserved_value.as_slice());
    let mut transactions = provisional.txdata;
    transactions[0].output[0].script_pubkey.as_mut_bytes()[6..38]
        .copy_from_slice(commitment.as_byte_array());
    transactions
}

fn fixture(outcome: RegtestExpectedOutcomeV2) -> RegtestInputFixtureV2 {
    let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "dom-f5-regtest-v2-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).expect("create isolated fixture directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("set owner-only fixture mode");

    let funding = FundingRef {
        txid: [0x44; 32],
        vout: 7,
        amount_sat: 100_000,
    };
    let raw_transaction = match outcome {
        RegtestExpectedOutcomeV2::Claim => build_signed_claim(&funding, &DESTINATION_SPK, FEE_SAT),
        RegtestExpectedOutcomeV2::Refund => {
            build_signed_refund(&funding, &DESTINATION_SPK, FEE_SAT)
        }
    };
    let transaction: Transaction =
        deserialize(&raw_transaction).expect("F5 transaction is canonical");
    let transactions = with_coinbase_witness_commitment(vec![transaction.clone()]);
    let genesis = genesis_block(Network::Regtest);
    let mut containing_block = Block {
        header: bitcoin::block::Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: genesis.block_hash(),
            merkle_root: TxMerkleNode::from_raw_hash(Hash::from_byte_array(merkle_root(
                &transactions,
            ))),
            time: genesis.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: transactions,
    };
    assert!(containing_block.check_merkle_root());
    assert!(containing_block.check_witness_commitment());
    mine_header(&mut containing_block.header);

    let mut successor = bitcoin::block::Header {
        version: BlockVersion::from_consensus(0x2000_0000),
        prev_blockhash: containing_block.block_hash(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: containing_block.header.time.saturating_add(1),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    mine_header(&mut successor);

    let settlement_id = [0x41; 32];
    let terms_hash = [0x42; 32];
    let genesis_ancestry = [raw_header(&genesis.header)];
    let authority = PinnedRegtestHeaderAuthorityV2::create_from_ancestry(
        &directory.join("authority"),
        MINIMUM_DEPTH,
        &genesis_ancestry,
    )
    .expect("create independently pinned authority");
    let observer_state = directory.join("observer-state");
    std::fs::create_dir(&observer_state).expect("create observer state directory");
    std::fs::set_permissions(&observer_state, std::fs::Permissions::from_mode(0o700))
        .expect("set owner-only observer state mode");
    let input = json!({
        "schema": "dom-f5-regtest-evidence-v2",
        "network_kind": "bitcoin-regtest-v2",
        "network_genesis": genesis.block_hash().to_string(),
        "settlement_id": hex(&settlement_id),
        "terms_hash": hex(&terms_hash),
        "expected_outpoint": {
            "txid": transaction.input[0].previous_output.txid.to_string(),
            "vout": transaction.input[0].previous_output.vout,
        },
        "outcome": match outcome {
            RegtestExpectedOutcomeV2::Claim => "claim",
            RegtestExpectedOutcomeV2::Refund => "refund",
        },
        "block_height": 1,
        "block_hash": containing_block.block_hash().to_string(),
        "block_hex": hex(&serialize(&containing_block)),
        "transaction_position": 1,
        "txid": transaction.compute_txid().to_string(),
        "wtxid": transaction.compute_wtxid().to_string(),
        "minimum_confirmation_depth": MINIMUM_DEPTH,
        "continuation_headers": [header_entry(1, &containing_block.header)],
        "confirmation_headers": [header_entry(2, &successor)],
    });

    RegtestInputFixtureV2 {
        directory,
        input,
        funding,
        settlement_id,
        terms_hash,
        outcome,
        authority,
        observer_state,
    }
}

#[test]
fn claim_and_refund_cross_the_v2_authority_and_replay_idempotently() {
    for outcome in [
        RegtestExpectedOutcomeV2::Claim,
        RegtestExpectedOutcomeV2::Refund,
    ] {
        let fixture = fixture(outcome);
        let path = fixture.write("evidence.json", &fixture.input);
        let expectation = fixture.expectation();
        let first = verify_regtest_evidence_file(
            &path,
            &expectation,
            &fixture.authority,
            &fixture.observer_state,
        )
        .expect("genesis-rooted V2 evidence is operational");
        let replay = verify_regtest_evidence_file(
            &path,
            &expectation,
            &fixture.authority,
            &fixture.observer_state,
        )
        .expect("byte-identical V2 evidence replay is idempotent");

        assert_eq!(first.confirmation_depth, 2);
        assert_eq!(first.total_transactions, 2);
        assert_eq!(first.transaction_position, 1);
        assert_ne!(first.evidence_digest, [0; 32]);
        assert_ne!(first.header_authority_digest, [0; 32]);
        assert_eq!(first.evidence_digest, replay.evidence_digest);
        assert_eq!(
            first.header_authority_digest,
            replay.header_authority_digest
        );
        assert!(first.economic_terminal_unique);
        assert!(first.observer_redelivery_idempotent);
    }
}

#[test]
fn route_self_nominated_checkpoint_policy_and_chain_tamper_fail_before_uspe() {
    let fixture = fixture(RegtestExpectedOutcomeV2::Claim);
    let expectation = fixture.expectation();

    let mut rerouted = fixture.input.clone();
    rerouted["terms_hash"] = Value::String(hex(&[0x99; 32]));
    let rerouted_path = fixture.write("rerouted.json", &rerouted);
    assert!(verify_regtest_evidence_file(
        &rerouted_path,
        &expectation,
        &fixture.authority,
        &fixture.observer_state
    )
    .err()
    .expect("rerouted evidence fails")
    .contains("frozen route expectation"));

    let mut self_nominated_checkpoint = fixture.input.clone();
    self_nominated_checkpoint["checkpoint_headers"] =
        json!([header_entry(0, &genesis_block(Network::Regtest).header)]);
    let checkpoint_path =
        fixture.write("self-nominated-checkpoint.json", &self_nominated_checkpoint);
    assert!(verify_regtest_evidence_file(
        &checkpoint_path,
        &expectation,
        &fixture.authority,
        &fixture.observer_state
    )
    .err()
    .expect("self-nominated checkpoint fails")
    .contains("unknown field"));

    let mut broken_successor = fixture.input.clone();
    broken_successor["confirmation_headers"][0] =
        header_entry(2, &genesis_block(Network::Regtest).header);
    broken_successor["confirmation_headers"][0]["height"] = json!(2);
    let broken_path = fixture.write("broken-successor.json", &broken_successor);
    assert!(verify_regtest_evidence_file(
        &broken_path,
        &expectation,
        &fixture.authority,
        &fixture.observer_state
    )
    .is_err());

    let insufficient_path = fixture.write("insufficient.json", &{
        let mut input = fixture.input.clone();
        input["minimum_confirmation_depth"] = json!(3);
        input
    });
    let stricter_authority = PinnedRegtestHeaderAuthorityV2::create_from_ancestry(
        &fixture.directory.join("stricter-authority"),
        3,
        &[raw_header(&genesis_block(Network::Regtest).header)],
    )
    .expect("create stricter independent authority");
    assert!(verify_regtest_evidence_file(
        &insufficient_path,
        &expectation,
        &stricter_authority,
        &fixture.observer_state
    )
    .is_err());
}

#[test]
fn canonical_json_and_hash_encodings_are_fail_closed() {
    let fixture = fixture(RegtestExpectedOutcomeV2::Claim);
    let expectation = fixture.expectation();

    let mut uppercase = fixture.input.clone();
    uppercase["txid"] = Value::String(
        uppercase["txid"]
            .as_str()
            .expect("txid is a string")
            .to_ascii_uppercase(),
    );
    let uppercase_path = fixture.write("uppercase.json", &uppercase);
    assert!(verify_regtest_evidence_file(
        &uppercase_path,
        &expectation,
        &fixture.authority,
        &fixture.observer_state
    )
    .err()
    .expect("uppercase hash fails")
    .contains("canonical lowercase hex"));

    let canonical = serde_json::to_string(&fixture.input).expect("fixture JSON encodes");
    let duplicate = canonical.replacen("{", "{\"schema\":\"dom-f5-regtest-evidence-v2\",", 1);
    let duplicate_path = fixture.directory.join("duplicate.json");
    std::fs::write(&duplicate_path, duplicate).expect("duplicate JSON writes");
    assert!(verify_regtest_evidence_file(
        &duplicate_path,
        &expectation,
        &fixture.authority,
        &fixture.observer_state
    )
    .err()
    .expect("duplicate field fails")
    .contains("duplicate field"));

    let mut unknown = fixture.input.clone();
    unknown["legacy_v1_fallback"] = json!(true);
    let unknown_path = fixture.write("unknown.json", &unknown);
    assert!(verify_regtest_evidence_file(
        &unknown_path,
        &expectation,
        &fixture.authority,
        &fixture.observer_state
    )
    .err()
    .expect("unknown field fails")
    .contains("unknown field"));
}

#[test]
fn observer_state_cannot_be_selected_through_evidence_or_symlinked_storage() {
    let fixture = fixture(RegtestExpectedOutcomeV2::Claim);
    let expectation = fixture.expectation();
    let path = fixture.write("observer-boundary.json", &fixture.input);

    let linked_state = fixture.directory.join("observer-state-link");
    symlink(&fixture.observer_state, &linked_state).expect("create observer-state symlink");
    assert!(
        verify_regtest_evidence_file(&path, &expectation, &fixture.authority, &linked_state)
            .err()
            .expect("symlinked observer state fails")
            .contains("owner-only storage")
    );

    let weak_state = fixture.directory.join("observer-state-weak");
    std::fs::create_dir(&weak_state).expect("create weak observer state");
    std::fs::set_permissions(&weak_state, std::fs::Permissions::from_mode(0o755))
        .expect("set weak observer mode");
    assert!(
        verify_regtest_evidence_file(&path, &expectation, &fixture.authority, &weak_state)
            .err()
            .expect("weak observer state fails")
            .contains("owner-only storage")
    );

    assert!(!path.with_extension("regtest-v2-observer.sqlite").exists());
}
