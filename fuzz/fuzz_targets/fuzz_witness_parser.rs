#![no_main]

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::block::{Header, Version};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use btc_evidence::{
    verify_evidence_v2, BitcoinEvidenceNetworkV2, BitcoinEvidenceRouteBindingV2,
    BitcoinHeaderPolicyBindingV2, BitcoinOutPointV2, BitcoinOutcomeV2, BitcoinTransactionClaimV2,
    KeystoneBitcoinEvidenceV2, RegtestHeaderAuthorityV2, RegtestHeaderCheckpointV2,
    RegtestHeaderPolicyV2,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_BYTES: usize = 2_048;
const MAX_WITNESS_ITEMS: usize = 6;
const MAX_WITNESS_ITEM_BYTES: usize = 128;

fn fuzz_witness(data: &[u8]) -> (BitcoinOutcomeV2, Witness) {
    let data = &data[..data.len().min(MAX_FUZZ_BYTES)];
    let selector = data.first().copied().unwrap_or_default();
    let outcome = if selector & 1 == 0 {
        BitcoinOutcomeV2::KeyPathClaim
    } else {
        BitcoinOutcomeV2::CsvScriptPathRefund
    };
    let item_count = usize::from(selector >> 1) % MAX_WITNESS_ITEMS;
    let mut cursor = usize::from(!data.is_empty());
    let mut witness = Witness::new();

    for _ in 0..item_count {
        let announced = data.get(cursor).copied().unwrap_or_default();
        cursor = cursor.saturating_add(1).min(data.len());
        let length = usize::from(announced).min(MAX_WITNESS_ITEM_BYTES);
        let end = cursor.saturating_add(length).min(data.len());
        witness.push(&data[cursor..end]);
        cursor = end;
    }
    (outcome, witness)
}

fn spending_transaction(witness: Witness) -> Transaction {
    Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(Hash::from_byte_array([0x42; 32])),
                vout: 7,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; 34]),
        }],
    }
}

fn with_witness_commitment(transaction: Transaction) -> Vec<Transaction> {
    let witness_reserved_value = [0u8; 32];
    let mut coinbase_witness = Witness::new();
    coinbase_witness.push(witness_reserved_value);
    let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment_script.extend_from_slice(&[0u8; 32]);
    let coinbase = Transaction {
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
    };
    let provisional = Block {
        header: Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
            nonce: 0,
        },
        txdata: vec![coinbase, transaction],
    };
    let witness_root = provisional
        .witness_root()
        .expect("coinbase plus fuzz transaction has a witness root");
    let commitment =
        Block::compute_witness_commitment(&witness_root, witness_reserved_value.as_slice());
    let mut transactions = provisional.txdata;
    transactions[0].output[0].script_pubkey.as_mut_bytes()[6..38]
        .copy_from_slice(commitment.as_byte_array());
    transactions
}

fn merkle_root(transactions: &[Transaction]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = transactions
        .iter()
        .map(|transaction| transaction.compute_txid().to_raw_hash().to_byte_array())
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
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

fn mine_header(mut header: Header) -> Option<Header> {
    let target = header.target();
    loop {
        if header.validate_pow(target).is_ok() {
            return Some(header);
        }
        header.nonce = header.nonce.checked_add(1)?;
    }
}

fn exercise_v2_witness(data: &[u8]) {
    let (outcome, witness) = fuzz_witness(data);
    let transactions = with_witness_commitment(spending_transaction(witness));
    let genesis = genesis_block(Network::Regtest);
    let containing_header = Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: genesis.block_hash(),
        merkle_root: TxMerkleNode::from_raw_hash(Hash::from_byte_array(merkle_root(&transactions))),
        time: genesis.header.time.saturating_add(1),
        bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
        nonce: 0,
    };
    let Some(containing_header) = mine_header(containing_header) else {
        return;
    };
    let block = Block {
        header: containing_header,
        txdata: transactions,
    };
    assert!(
        block.check_witness_commitment(),
        "fuzz fixture must authenticate the exact witness"
    );

    let successor = Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: block.block_hash(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: block.header.time.saturating_add(1),
        bits: CompactTarget::from_consensus(RegtestHeaderPolicyV2::EXPECTED_BITS),
        nonce: 0,
    };
    let Some(successor) = mine_header(successor) else {
        return;
    };
    let successor_raw: [u8; 80] = serialize(&successor)
        .try_into()
        .expect("a consensus header is exactly 80 bytes");

    let policy = RegtestHeaderPolicyV2::new(2).expect("depth two is valid on Regtest");
    let checkpoint =
        RegtestHeaderCheckpointV2::genesis().expect("the canonical Regtest genesis is valid");
    let spending = &block.txdata[1];
    let previous_output = spending.input[0].previous_output;
    let evidence = KeystoneBitcoinEvidenceV2::new(
        BitcoinEvidenceRouteBindingV2::new([1; 32], [2; 32])
            .expect("fixed V2 route binding is valid"),
        BitcoinHeaderPolicyBindingV2::new(
            BitcoinEvidenceNetworkV2::Regtest,
            genesis.block_hash().to_raw_hash().to_byte_array(),
            1,
            policy.digest(),
            checkpoint.digest(),
            2,
        )
        .expect("fixed Regtest policy binding is valid"),
        BitcoinTransactionClaimV2::new(
            spending.compute_txid().to_raw_hash().to_byte_array(),
            spending.compute_wtxid().to_raw_hash().to_byte_array(),
            BitcoinOutPointV2::new(
                previous_output.txid.to_raw_hash().to_byte_array(),
                previous_output.vout,
            )
            .expect("fixed non-zero outpoint is valid"),
            2,
            1,
            outcome,
        )
        .expect("fuzz transaction claim is structurally valid"),
        serialize(&block),
        vec![successor_raw],
    )
    .expect("constructed V2 evidence is bounded");
    let containing_header_raw: [u8; 80] = serialize(&block.header)
        .try_into()
        .expect("a consensus header is exactly 80 bytes");
    let authority = RegtestHeaderAuthorityV2::new(policy, checkpoint);
    let authenticated = authority
        .authenticate(&evidence, &[containing_header_raw])
        .expect("constructed Regtest header chain authenticates");

    // The result may accept or reject the fuzz-selected witness shape. Either
    // way it has traversed the mandatory complete-block, mutation, ambiguity,
    // witness-commitment, txid/wtxid, outpoint and witness-shape V2 checks.
    let _ = verify_evidence_v2(&evidence, &authenticated);
}

fuzz_target!(|data: &[u8]| {
    exercise_v2_witness(data);
});
