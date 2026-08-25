//! Evidence verifier tests (Annex M M.9.3, M.9.4, M.9.5). A regtest block
//! is built with rust-bitcoin so the header, Merkle root and witness are
//! genuine; the verifier must accept it and reject every tampering.

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::block::{Header, Version};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, Witness,
};

use btc_evidence::{
    verified_outcome_to_uspe_event, verify_evidence, BitcoinEvidenceNetworkV1, BitcoinOutPointV1,
    BitcoinOutcomeV1, BoundedMerkleBranchV1, KeystoneBitcoinEvidenceV1,
};

/// Builds a single-transaction regtest block whose one tx spends
/// `prev_out` with the given witness, and mines it to satisfy the (easy)
/// regtest-style target of the header we set.
fn build_block(prev_out: OutPoint, witness: Witness) -> (Header, Transaction) {
    let tx = Transaction {
        version: TxVersion(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev_out,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x01, 0x01]),
        }],
    };
    // Single-tx block: the Merkle root is the tx's txid.
    let merkle_root = TxMerkleNode::from_raw_hash(tx.compute_txid().to_raw_hash());
    let mut header = Header {
        version: Version::from_consensus(0x2000_0000),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root,
        time: 1_700_000_000,
        // The maximum-permitted target (regtest limit): almost any hash
        // meets it, so a tiny nonce grind succeeds deterministically.
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let target = header.target();
    // Deterministic grind (bounded) — regtest target is trivially met.
    loop {
        if header.validate_pow(target).is_ok() {
            break;
        }
        header.nonce += 1;
    }
    (header, tx)
}

fn confirmations(prev: BlockHash, n: usize) -> Vec<[u8; 80]> {
    let mut out = Vec::new();
    let mut parent = prev;
    for i in 0..n {
        let mut h = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: parent,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_100 + i as u32,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let target = h.target();
        while h.validate_pow(target).is_err() {
            h.nonce += 1;
        }
        parent = h.block_hash();
        let mut raw = [0u8; 80];
        raw.copy_from_slice(&serialize(&h));
        out.push(raw);
    }
    out
}

fn keypath_witness() -> Witness {
    let mut w = Witness::new();
    w.push([0x11u8; 64]); // a 64-byte BIP340 signature (shape only)
    w
}

fn evidence_for(
    header: &Header,
    tx: &Transaction,
    outcome: BitcoinOutcomeV1,
) -> KeystoneBitcoinEvidenceV1 {
    let mut raw_header = [0u8; 80];
    raw_header.copy_from_slice(&serialize(header));
    let block_hash = header.block_hash();
    KeystoneBitcoinEvidenceV1 {
        codec_version: 1,
        network: BitcoinEvidenceNetworkV1::Regtest,
        network_genesis_hash: genesis_block(Network::Regtest)
            .block_hash()
            .to_raw_hash()
            .to_byte_array(),
        settlement_id: [0x10; 32],
        terms_hash: [0x13; 32],
        expected_outpoint: BitcoinOutPointV1 {
            txid: tx.input[0]
                .previous_output
                .txid
                .to_raw_hash()
                .to_byte_array(),
            vout: tx.input[0].previous_output.vout,
        },
        raw_transaction: serialize(tx),
        txid: tx.compute_txid().to_raw_hash().to_byte_array(),
        wtxid: tx.compute_wtxid().to_raw_hash().to_byte_array(),
        block_header: raw_header,
        block_height: 42,
        // Single-tx block: empty branch, position 0.
        txid_merkle_branch: BoundedMerkleBranchV1 {
            siblings: Vec::new(),
            position: 0,
        },
        confirmation_headers: confirmations(block_hash, 3),
        outcome,
    }
}

#[test]
fn valid_keypath_evidence_verifies_and_bridges_to_uspe() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    let (header, tx) = build_block(prev, keypath_witness());
    let evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);

    let outcome = verify_evidence(&evidence).expect("valid evidence");
    assert_eq!(outcome.outcome, BitcoinOutcomeV1::KeyPathClaim);
    assert_eq!(outcome.terms_hash, [0x13; 32]);
    assert_eq!(outcome.confirmation_depth, 3);

    // The USPE bridge carries ONLY the terms binding — no secret material.
    let event = verified_outcome_to_uspe_event(&outcome);
    match event {
        uspe::AssuranceEvent::CompensationClaimed { terms_hash } => {
            assert_eq!(terms_hash, [0x13; 32]);
        }
        _ => panic!("unexpected event"),
    }
}

#[test]
fn tampered_txid_is_rejected() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    let (header, tx) = build_block(prev, keypath_witness());
    let mut evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);
    evidence.txid[0] ^= 0x01;
    // The tampered txid breaks Merkle inclusion (root no longer matches).
    assert!(verify_evidence(&evidence).is_err());
}

#[test]
fn public_signet_evidence_with_a_foreign_genesis_is_rejected() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    let (header, tx) = build_block(prev, keypath_witness());
    let mut evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);
    evidence.network = BitcoinEvidenceNetworkV1::PublicSignet;
    // Keep the regtest genesis from `evidence_for`: it must not be accepted
    // merely because the rest of the transaction proof is well formed.
    assert_eq!(
        verify_evidence(&evidence).unwrap_err(),
        btc_evidence::EvidenceError::NetworkGenesisMismatch
    );
}

#[test]
fn sixty_five_byte_keypath_signature_is_rejected() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    let mut w = Witness::new();
    w.push([0x11u8; 65]); // 65-byte signature: forbidden on the key path.
    let (header, tx) = build_block(prev, w);
    let evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);
    assert_eq!(
        verify_evidence(&evidence).unwrap_err(),
        btc_evidence::EvidenceError::WitnessShapeInvalid
    );
}

#[test]
fn annex_is_rejected() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    // Two elements, the last an annex (starts with 0x50): forbidden.
    let mut w = Witness::new();
    w.push([0x11u8; 64]);
    w.push([0x50u8, 0xde, 0xad]);
    let (header, tx) = build_block(prev, w);
    let evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);
    assert_eq!(
        verify_evidence(&evidence).unwrap_err(),
        btc_evidence::EvidenceError::WitnessShapeInvalid
    );
}

#[test]
fn wrong_outpoint_is_rejected() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    let (header, tx) = build_block(prev, keypath_witness());
    let mut evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);
    evidence.expected_outpoint.vout = 7; // not the outpoint the tx spends
    assert_eq!(
        verify_evidence(&evidence).unwrap_err(),
        btc_evidence::EvidenceError::OutpointNotSpent
    );
}

#[test]
fn missing_confirmations_are_rejected() {
    let prev = OutPoint {
        txid: Txid::from_raw_hash(Hash::from_byte_array([0x22; 32])),
        vout: 0,
    };
    let (header, tx) = build_block(prev, keypath_witness());
    let mut evidence = evidence_for(&header, &tx, BitcoinOutcomeV1::KeyPathClaim);
    evidence.confirmation_headers.clear();
    assert_eq!(
        verify_evidence(&evidence).unwrap_err(),
        btc_evidence::EvidenceError::InsufficientConfirmations
    );
}
