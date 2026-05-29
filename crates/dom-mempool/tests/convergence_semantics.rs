use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{Amount, DomError, KERNEL_FEAT_PLAIN, MIN_RELAY_FEE_RATE};
use dom_crypto::pedersen::Commitment;
use dom_mempool::{validate_tx_against_chain_view, Mempool};
use dom_store::utxo::UtxoEntry;

fn g_commitment() -> Commitment {
    let g = [
        0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    Commitment::from_compressed_bytes(&g).unwrap()
}

fn h_commitment() -> Commitment {
    let h = [
        0x02u8, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1,
        0x7b, 0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f,
        0x09, 0xd5, 0x50,
    ];
    Commitment::from_compressed_bytes(&h).unwrap()
}

fn make_spending_tx(input_commitment: Commitment, fee: u64, seed: u8) -> (Transaction, [u8; 32]) {
    let tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: g_commitment(),
            proof: vec![seed; 100],
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess: h_commitment(),
            excess_signature: [seed; 65],
        }],
        offset: [0u8; 32],
    };
    let mut hash = [0u8; 32];
    hash[0..8].copy_from_slice(&fee.to_le_bytes());
    hash[8] = seed;
    (tx, hash)
}

#[test]
fn conflicting_spend_is_rejected_while_original_is_in_pool() {
    let mut pool = Mempool::new();
    let input = h_commitment();
    let (first, first_hash) = make_spending_tx(input.clone(), MIN_RELAY_FEE_RATE * 25, 0x01);
    let (conflict, conflict_hash) = make_spending_tx(input, MIN_RELAY_FEE_RATE * 26, 0x02);

    pool.accept_tx(first, first_hash, 0).expect("first accept");
    let err = pool
        .accept_tx(conflict, conflict_hash, 1)
        .expect_err("conflicting spend must be rejected");
    assert!(
        matches!(err, DomError::PolicyRejected(ref msg) if msg.contains("input already reserved by mempool tx")),
        "expected mempool conflict rejection, got {err}"
    );
}

#[test]
fn conflicting_spend_can_be_reaccepted_after_confirmed_cleanup() {
    let mut pool = Mempool::new();
    let input = h_commitment();
    let (first, first_hash) = make_spending_tx(input.clone(), MIN_RELAY_FEE_RATE * 25, 0x01);
    let (conflict, conflict_hash) = make_spending_tx(input.clone(), MIN_RELAY_FEE_RATE * 26, 0x02);

    pool.accept_tx(first, first_hash, 0).expect("first accept");
    pool.remove_confirmed(&[*input.as_bytes()]);
    pool.accept_tx(conflict, conflict_hash, 1)
        .expect("cleanup must release the input reservation");
    assert!(pool.get_tx(&conflict_hash).is_some());
}

/// TASK 29 / RFC-0012 §4 (mempool half of Policy B): a transaction that spends an
/// output created by an as-yet-unconfirmed sibling (a same-block / parent-child
/// spend) is rejected at admission, because that output is not in the canonical
/// UTXO set. Only once the parent's output is confirmed does the child become
/// admissible. This is why the miner — which templates only admitted mempool
/// transactions — can never assemble a same-block spend.
#[test]
fn same_block_child_spend_rejected_until_parent_output_is_confirmed() {
    // `parent_output` stands in for an output created by an unconfirmed sibling
    // transaction in the (would-be) same block.
    let parent_output = h_commitment();
    let (child, child_hash) = make_spending_tx(parent_output, MIN_RELAY_FEE_RATE * 25, 0x07);

    // Parent output is NOT in the canonical UTXO set (unconfirmed) → reject.
    let mut pool = Mempool::new();
    let err = pool
        .accept_tx_with_chain_view(child.clone(), child_hash, 0, 100, 10, |_| Ok(None))
        .expect_err("same-block child spend must be rejected while the parent is unconfirmed");
    assert!(
        matches!(err, DomError::PolicyRejected(ref msg) if msg.contains("not found in canonical UTXO set")),
        "expected unconfirmed-parent rejection, got {err}"
    );
    assert!(
        pool.get_tx(&child_hash).is_none(),
        "rejected child must not enter the pool"
    );

    // Once the parent's output is a confirmed, mature UTXO, the child admits.
    let confirmed_parent = UtxoEntry {
        block_height: 1,
        is_coinbase: false,
        proof: vec![],
    };
    pool.accept_tx_with_chain_view(child, child_hash, 0, 100, 10, |_| {
        Ok(Some(confirmed_parent.clone()))
    })
    .expect("child admits once its parent output is confirmed");
    assert!(pool.get_tx(&child_hash).is_some());
}

#[test]
fn chain_view_rejects_missing_input() {
    let input = h_commitment();
    let (tx, _) = make_spending_tx(input, MIN_RELAY_FEE_RATE * 25, 0x01);

    let err = validate_tx_against_chain_view(&tx, 100, 1_000, |_| Ok(None))
        .expect_err("missing input must reject");
    assert!(
        matches!(err, DomError::PolicyRejected(ref msg) if msg.contains("not found in canonical UTXO set")),
        "expected missing-input rejection, got {err}"
    );
}

#[test]
fn chain_view_rejects_immature_coinbase() {
    let input = h_commitment();
    let (tx, _) = make_spending_tx(input, MIN_RELAY_FEE_RATE * 25, 0x01);
    let entry = UtxoEntry {
        block_height: 100,
        is_coinbase: true,
        proof: vec![],
    };

    let err = validate_tx_against_chain_view(&tx, 100, 10, |_| Ok(Some(entry.clone())))
        .expect_err("immature coinbase must reject");
    assert!(
        matches!(err, DomError::TemporarilyInvalid(ref msg) if msg.contains("immature coinbase spend")),
        "expected immature-coinbase rejection, got {err}"
    );
}

#[test]
fn chain_view_accepts_present_mature_inputs() {
    let input = h_commitment();
    let (tx, hash) = make_spending_tx(input, MIN_RELAY_FEE_RATE * 25, 0x01);
    let entry = UtxoEntry {
        block_height: 10,
        is_coinbase: true,
        proof: vec![],
    };
    let mut pool = Mempool::new();

    pool.accept_tx_with_chain_view(tx, hash, 0, 25, 10, |_| Ok(Some(entry.clone())))
        .expect("mature canonical input must be accepted");
    assert!(pool.get_tx(&hash).is_some());
}

#[test]
fn reinjection_with_chain_view_is_permutation_invariant() {
    let input = h_commitment();
    let entry = UtxoEntry {
        block_height: 10,
        is_coinbase: false,
        proof: vec![],
    };
    let (tx_a, hash_a) = make_spending_tx(input.clone(), MIN_RELAY_FEE_RATE * 26, 0x01);
    let (tx_b, hash_b) = make_spending_tx(input, MIN_RELAY_FEE_RATE * 27, 0x02);

    let mut forward = Mempool::new();
    let forward_results = forward.reinject_batch_with_chain_view(
        vec![(tx_b.clone(), hash_b, 2), (tx_a.clone(), hash_a, 1)],
        100,
        1_000,
        |_| Ok(Some(entry.clone())),
    );

    let mut reverse = Mempool::new();
    let reverse_results = reverse.reinject_batch_with_chain_view(
        vec![(tx_a, hash_a, 1), (tx_b, hash_b, 2)],
        100,
        1_000,
        |_| Ok(Some(entry.clone())),
    );

    let winner = hash_a.min(hash_b);
    assert_eq!(forward.all_hashes(), vec![winner]);
    assert_eq!(reverse.all_hashes(), vec![winner]);
    assert_eq!(
        forward_results
            .iter()
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>(),
        reverse_results
            .iter()
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>(),
    );
}
